from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import shutil
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.datastructures import UploadFile
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings
from app.cloudflare import CloudflareClient, CloudflareError, DnsRecordInput, normalize_record, validate_id
from app.db import Store
from app.dns_locks import zone_write_lock
from app.host_keys import key_summary, probe_host_key, read_host_keys, replace_host_key
from app.remote import RemoteJobError
from app.security import LoginLimiter, hash_password, secret_box, validate_domain, validate_target, validate_username, verify_password
from app.worker import JobWorker

MAX_UPLOAD = 50 * 1024 * 1024
VERSIONS = {"v2.9.4", "v3.4.2"}
DNS_RECORD_LIMIT = 100
ROOT = Path(__file__).parent


def asset_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def random_panel_port(ssh_port: int, excluded=()) -> int:
    reserved = {22, 80, ssh_port, *excluded}
    available = [port for port in range(10000, 60001) if port not in reserved]
    if not available:
        raise ValueError("没有可分配的临时面板端口，请检查数据库中的端口配置。")
    return secrets.choice(available)


def check_panel_port(port: int, ssh_port: int) -> int:
    if not 1 <= port <= 65535 or port in {22, 80, ssh_port}:
        raise ValueError("面板端口须为 1–65535，且不能使用 22、证书验证端口 80 或目标 SSH 端口。")
    return port


class RequestTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(self, app, limit: int = MAX_UPLOAD + 1024 * 1024):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        size = 0

        async def limited_receive():
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > self.limit:
                raise RequestTooLarge()
            return message

        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    if int(value) > self.limit:
                        return await JSONResponse({"detail": "上传文件不能超过 50 MiB。"}, status_code=413)(scope, receive, send)
                except ValueError:
                    return await JSONResponse({"detail": "无效的请求长度。"}, status_code=400)(scope, receive, send)
        try:
            await self.app(scope, limited_receive, send)
        except RequestTooLarge:
            await JSONResponse({"detail": "上传文件不能超过 50 MiB。"}, status_code=413)(scope, receive, send)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserInput(LoginInput):
    password: str = Field(min_length=12, max_length=256)


class ActiveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool


class RetryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ssh_password: str = Field(min_length=1, max_length=1024)


class HostKeyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation_token: str = Field(min_length=1, max_length=16384)


class CloudflareInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: str = Field(pattern=r"^[a-fA-F0-9]{32}$")
    api_token: SecretStr | None = Field(default=None, max_length=1024)


class DomainGrantInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    zone_ids: list[str] = Field(max_length=1000)


def public_user(user: dict | None) -> dict | None:
    if not user:
        return None
    return {key: user[key] for key in ("id", "username", "role", "active")}


def public_task(task: dict) -> dict:
    return {key: value for key, value in task.items() if key not in {"encrypted_password", "upload_path"}}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    settings.data_dir.chmod(0o700)
    upload_dir = settings.data_dir / "uploads"
    upload_dir.mkdir(mode=0o700, exist_ok=True)
    store = Store(settings.database)
    box = secret_box(settings.secret)
    limiter = LoginLimiter()
    dummy_hash = hash_password(secrets.token_urlsafe(24))
    worker = JobWorker(store, settings)

    def execution_status() -> dict:
        return worker.runtime_status()

    def require_execution() -> None:
        execution = execution_status()
        if not execution["available"]:
            raise HTTPException(503, execution["message"] + " 本次未创建任务，请等待恢复后重新提交。")

    def task_response(task: dict, execution: dict, snapshot: dict | None = None) -> dict:
        result = public_task(task)
        if task["status"] != "queued":
            return result
        snapshot = snapshot or store.queue_snapshot()
        position = snapshot["positions"].get(task["id"], 1)
        active = execution.get("active_jobs", snapshot["running"])
        capacity = execution.get("capacity", 0)
        wait = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(task["created_at"])).total_seconds()))
        if not execution["available"]:
            message = execution["message"] + " 此任务尚未开始执行。"
        elif active >= capacity:
            message = f"当前排队第 {position} 位，已有 {active}/{capacity} 个任务执行中；空出执行名额后自动开始。"
        elif wait >= 30:
            message = f"当前排队第 {position} 位，已等待 {wait} 秒。执行器在线，正在等待领取；持续未开始时请管理员检查执行器状态。"
        else:
            message = f"当前排队第 {position} 位，执行器已就绪，等待领取任务。"
        result["queue_info"] = {"position": position, "active_jobs": active, "capacity": capacity, "wait_seconds": wait, "message": message}
        return result

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.enable_worker:
            await worker.start()
        try:
            yield
        finally:
            if settings.enable_worker:
                await worker.stop()

    app = FastAPI(title="3x-ui 部署控制台", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings, app.state.worker = store, settings, worker
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=settings.secret, session_cookie="xui_console", max_age=28800, same_site="strict", https_only=settings.cookie_secure)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
    templates = Jinja2Templates(directory=ROOT / "templates")

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        if request.url.path.startswith("/api") or response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo input values: they may contain SSH or account passwords.
        return JSONResponse({"detail": "提交的数据格式或长度不符合要求。"}, status_code=422)

    def csrf(request: Request) -> None:
        expected = request.session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            raise HTTPException(403, "页面会话已失效，请刷新后重试。")

    def current(request: Request, admin: bool = False) -> dict:
        user = store.user(request.session.get("user_id", -1))
        if not user or not user["active"] or request.session.get("session_version") != user["session_version"]:
            request.session.pop("user_id", None)
            raise HTTPException(401, "请先登录网站。")
        if admin and user["role"] != "admin":
            raise HTTPException(403, "只有管理员可以操作。")
        return user

    def get_task(request: Request, task_id: str) -> dict:
        user = current(request)
        task = store.task(task_id)
        if not task or (task["user_id"] != user["id"] and user["role"] != "admin"):
            raise HTTPException(404, "任务不存在。")
        return task

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        versions = {name: asset_digest(ROOT / "static" / name) for name in ("app.js", "style.css")}
        return templates.TemplateResponse(request=request, name="index.html", context={"asset_versions": versions})

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "execution": execution_status()}

    @app.get("/api/ready")
    async def ready():
        execution = execution_status()
        return JSONResponse({"status": "ready" if execution["available"] else "unavailable", "execution": execution}, status_code=200 if execution["available"] else 503)

    @app.get("/api/me")
    async def me(request: Request):
        request.session.setdefault("csrf_token", secrets.token_urlsafe(32))
        user = store.user(request.session.get("user_id", -1))
        if user and (not user["active"] or request.session.get("session_version") != user["session_version"]):
            request.session.pop("user_id", None)
            user = None
        return {"user": public_user(user), "csrf_token": request.session["csrf_token"], "execution": execution_status()}

    @app.post("/api/login")
    async def login(request: Request, data: LoginInput):
        csrf(request)
        key = request.client.host if request.client else "unknown"
        if not limiter.allow(key):
            raise HTTPException(429, "登录尝试过多，请 15 分钟后再试。")
        user = store.user_by_name(data.username.strip())
        correct = verify_password(data.password, user["password_hash"] if user else dummy_hash)
        if not user or not correct or not user["active"]:
            raise HTTPException(401, "用户名或密码错误，或账号已停用。")
        limiter.success(key)
        request.session.clear()
        request.session.update(user_id=user["id"], session_version=user["session_version"], csrf_token=secrets.token_urlsafe(32))
        return {"user": public_user(user), "csrf_token": request.session["csrf_token"], "execution": execution_status()}

    @app.post("/api/logout")
    async def logout(request: Request):
        csrf(request)
        request.session.clear()
        request.session["csrf_token"] = secrets.token_urlsafe(32)
        return {"ok": True, "csrf_token": request.session["csrf_token"]}

    @app.get("/api/admin/users")
    async def list_users(request: Request):
        current(request, admin=True)
        return {"users": store.users()}

    @app.post("/api/admin/users", status_code=201)
    async def add_user(request: Request, data: UserInput):
        csrf(request)
        current(request, admin=True)
        try:
            username = validate_username(data.username)
            user = store.add_user(username, hash_password(data.password))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except sqlite3.IntegrityError:
            raise HTTPException(409, "这个用户名已存在。") from None
        return {"user": user}

    @app.patch("/api/admin/users/{user_id}")
    async def toggle_user(request: Request, user_id: int, data: ActiveInput):
        csrf(request)
        current(request, admin=True)
        if not store.set_user_active(user_id, data.active):
            raise HTTPException(404, "客户不存在，或该账号是管理员。")
        return {"ok": True}

    def cloudflare_configuration() -> dict:
        saved = store.integration("cloudflare")
        return {"configured": bool(saved), "account_id": saved["account_id"] if saved else "",
                "updated_at": saved["updated_at"] if saved else None}

    def cloudflare_credentials() -> tuple[str, str]:
        saved = store.integration("cloudflare")
        if not saved:
            raise HTTPException(409, "尚未配置 Cloudflare，请先填写账户 ID 和 API 令牌并保存。")
        try:
            return saved["account_id"], box.decrypt(saved["encrypted_token"].encode()).decode()
        except (InvalidToken, UnicodeError, ValueError):
            raise HTTPException(409, "Cloudflare 令牌无法解密，请管理员重新填写并保存 API 令牌。") from None

    def require_dns_access(user: dict, account_id: str, zone_id: str) -> None:
        saved = store.integration("cloudflare")
        if not saved or saved["account_id"] != account_id:
            raise HTTPException(409, "Cloudflare 账户配置已变化，请刷新后重试。")
        if user["role"] != "admin" and not store.has_domain_access(user["id"], account_id, zone_id):
            raise HTTPException(403, "你没有此域名的 DNS 操作权限，请联系管理员分配。")

    def dns_user(request: Request) -> dict:
        # Keep the old administrator URLs private while sharing their logic.
        return current(request, admin=request.url.path.startswith("/api/admin/"))

    def public_zone(zone: dict) -> dict:
        return {key: zone[key] for key in ("id", "name", "status") if key in zone}

    @asynccontextmanager
    async def cloudflare_connection(zone_id: str | None = None, user: dict | None = None):
        account_id, token = cloudflare_credentials()
        try:
            zone_id = validate_id(zone_id) if zone_id is not None else None
            if user is not None and zone_id is not None:
                require_dns_access(user, account_id, zone_id)
            async with CloudflareClient(token, account_id) as client:
                zone = await client.get_zone(zone_id) if zone_id is not None else None
                if user is not None and zone is not None:
                    require_dns_access(user, account_id, zone["id"])
                yield client, zone
        except CloudflareError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None

    @app.get("/api/admin/cloudflare")
    async def cloudflare_settings(request: Request):
        current(request, admin=True)
        return cloudflare_configuration()

    @app.put("/api/admin/cloudflare")
    async def save_cloudflare_settings(request: Request, data: CloudflareInput):
        csrf(request)
        current(request, admin=True)
        token = data.api_token.get_secret_value().strip() if data.api_token is not None else ""
        if not token:
            _, token = cloudflare_credentials()
        if not token.isascii() or any(character.isspace() for character in token):
            raise HTTPException(422, "Cloudflare API 令牌格式无效，请重新复制完整令牌。")
        account_id = data.account_id.lower()
        try:
            async with CloudflareClient(token, account_id) as client:
                zones = await client.list_zones()
        except CloudflareError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
        store.save_integration("cloudflare", account_id, box.encrypt(token.encode()).decode())
        return {"configuration": cloudflare_configuration(), "zones": zones}

    def domain_customer(user_id: int) -> dict:
        user = store.user(user_id)
        if not user or user["role"] != "customer":
            raise HTTPException(404, "客户不存在，或该账号是管理员。")
        return user

    @app.get("/api/admin/users/{user_id}/domains")
    async def customer_domains(request: Request, user_id: int):
        current(request, admin=True)
        user = domain_customer(user_id)
        account_id, _ = cloudflare_credentials()
        async with cloudflare_connection() as (client, _):
            zones = await client.list_zones()
        assigned = {zone["id"] for zone in store.user_domains(user_id, account_id)}
        return {"user": public_user(user), "zones": [public_zone(zone) for zone in zones],
                "assigned_zone_ids": [zone["id"] for zone in zones if zone["id"] in assigned],
                "record_limit": DNS_RECORD_LIMIT}

    @app.put("/api/admin/users/{user_id}/domains")
    async def assign_customer_domains(request: Request, user_id: int, data: DomainGrantInput):
        csrf(request)
        current(request, admin=True)
        domain_customer(user_id)
        account_id, _ = cloudflare_credentials()
        try:
            zone_ids = list(dict.fromkeys(validate_id(zone_id) for zone_id in data.zone_ids))
        except CloudflareError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
        selected = []
        if zone_ids:
            async with cloudflare_connection() as (client, _):
                available = {zone["id"]: zone for zone in await client.list_zones()}
            if any(zone_id not in available for zone_id in zone_ids):
                raise HTTPException(422, "待分配的域名不属于当前 Cloudflare 账户，或已不可用；请刷新域名列表。")
            selected = [available[zone_id] for zone_id in zone_ids]
        try:
            store.set_user_domains(user_id, account_id, selected)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        return {"assigned_zone_ids": zone_ids, "record_limit": DNS_RECORD_LIMIT}

    @app.get("/api/admin/cloudflare/zones")
    @app.get("/api/dns/zones")
    async def cloudflare_zones(request: Request):
        user = dns_user(request)
        allowed = None
        if user["role"] != "admin":
            saved = store.integration("cloudflare")
            allowed = {zone["id"] for zone in store.user_domains(user["id"], saved["account_id"])} if saved else set()
            if not allowed:
                return {"zones": [], "record_limit": DNS_RECORD_LIMIT}
        async with cloudflare_connection() as (client, _):
            zones = await client.list_zones()
            if allowed is not None:
                # Check again after the network request in case access changed.
                saved = store.integration("cloudflare")
                allowed = {zone["id"] for zone in store.user_domains(user["id"], client.account_id)} if saved and saved["account_id"] == client.account_id else set()
            return {"zones": [public_zone(zone) for zone in zones if allowed is None or zone["id"] in allowed], "record_limit": DNS_RECORD_LIMIT}

    @app.get("/api/admin/cloudflare/zones/{zone_id}/records")
    @app.get("/api/dns/zones/{zone_id}/records")
    async def cloudflare_records(request: Request, zone_id: str):
        user = dns_user(request)
        async with cloudflare_connection(zone_id, user) as (client, zone):
            records = await client.list_records(zone["id"])
            require_dns_access(user, client.account_id, zone["id"])
            return {"zone": public_zone(zone), "records": records, "record_limit": DNS_RECORD_LIMIT}

    @app.post("/api/admin/cloudflare/zones/{zone_id}/records", status_code=201)
    @app.post("/api/dns/zones/{zone_id}/records", status_code=201)
    async def create_cloudflare_record(request: Request, zone_id: str, data: DnsRecordInput):
        csrf(request)
        user = dns_user(request)
        async with cloudflare_connection(zone_id, user) as (client, zone):
            payload = normalize_record(data, zone["name"])
            async with zone_write_lock(settings.data_dir, client.account_id, zone["id"]):
                require_dns_access(user, client.account_id, zone["id"])
                records = await client.list_records(zone["id"])
                if len(records) >= DNS_RECORD_LIMIT:
                    raise HTTPException(409, "此域名已达到 100 条 DNS 记录上限，请先删除不需要的记录。")
                require_dns_access(user, client.account_id, zone["id"])
                return {"record": await client.create_record(zone["id"], payload)}

    @app.put("/api/admin/cloudflare/zones/{zone_id}/records/{record_id}")
    @app.put("/api/dns/zones/{zone_id}/records/{record_id}")
    async def update_cloudflare_record(request: Request, zone_id: str, record_id: str, data: DnsRecordInput):
        csrf(request)
        user = dns_user(request)
        async with cloudflare_connection(zone_id, user) as (client, zone):
            record_id = validate_id(record_id)
            payload = normalize_record(data, zone["name"])
            async with zone_write_lock(settings.data_dir, client.account_id, zone["id"]):
                require_dns_access(user, client.account_id, zone["id"])
                return {"record": await client.update_record(zone["id"], record_id, payload)}

    @app.delete("/api/admin/cloudflare/zones/{zone_id}/records/{record_id}")
    @app.delete("/api/dns/zones/{zone_id}/records/{record_id}")
    async def delete_cloudflare_record(request: Request, zone_id: str, record_id: str):
        csrf(request)
        user = dns_user(request)
        async with cloudflare_connection(zone_id, user) as (client, zone):
            record_id = validate_id(record_id)
            async with zone_write_lock(settings.data_dir, client.account_id, zone["id"]):
                require_dns_access(user, client.account_id, zone["id"])
                await client.delete_record(zone["id"], record_id)
        return {"deleted": True}

    @app.get("/api/tasks")
    async def tasks(request: Request):
        user = current(request)
        execution = execution_status()
        snapshot = store.queue_snapshot()
        return {"tasks": [task_response(task, execution, snapshot) for task in store.tasks(None if user["role"] == "admin" else user["id"])], "execution": execution}

    @app.get("/api/tasks/{task_id}")
    async def task_detail(request: Request, task_id: str):
        task = get_task(request, task_id)
        execution = execution_status()
        return {"task": task_response(task, execution), "events": store.events(task_id), "execution": execution}

    def host_key_task(request: Request, task_id: str) -> tuple[dict, dict]:
        user = current(request)
        task = get_task(request, task_id)
        if task["status"] not in {"failed", "interrupted"}:
            raise HTTPException(409, "只能为失败或中断的任务核实服务器指纹。")
        if store.has_active_target(task["server_ip"]):
            raise HTTPException(409, "该服务器还有等待或执行中的任务，请结束后再更新指纹。")
        try:
            validate_target(task["server_ip"], settings.allow_private_targets)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return user, task

    @app.get("/api/tasks/{task_id}/ssh-host-key")
    async def inspect_host_key(request: Request, task_id: str):
        user, task = host_key_task(request, task_id)
        host, port = task["server_ip"], task["ssh_port"]
        try:
            stored = read_host_keys(settings.data_dir / "ssh" / "known_hosts", host, port)
            observed = await probe_host_key(host, port)
            changed = bool(stored and observed not in stored)
            token = box.encrypt(json.dumps({
                "purpose": "ssh-host-key", "task_id": task_id, "user_id": user["id"],
                "host": host, "port": port, "stored_keys": stored, "observed_key": observed,
            }).encode()).decode() if changed else ""
            return {
                "host": host, "port": port, "stored_fingerprints": [key_summary(key) for key in stored],
                "observed": key_summary(observed), "changed": changed, "confirmation_token": token,
                "message": "请通过服务器服务商的控制台核对当前指纹；确认属于自己的服务器后才能信任。" if changed else
                           "当前服务器指纹与已保存记录一致，可以重新输入 SSH 密码重试。" if stored else
                           "尚无已保存的服务器指纹，下一次连接会记录首次指纹。",
            }
        except RemoteJobError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/api/tasks/{task_id}/ssh-host-key")
    async def confirm_host_key(request: Request, task_id: str, data: HostKeyInput):
        csrf(request)
        user, task = host_key_task(request, task_id)
        try:
            preview = json.loads(box.decrypt(data.confirmation_token.encode(), ttl=600))
        except (InvalidToken, ValueError, TypeError, UnicodeError):
            raise HTTPException(409, "指纹确认已失效或无效，请重新核实后操作。") from None
        if not isinstance(preview, dict) or any(preview.get(key) != value for key, value in {
            "purpose": "ssh-host-key", "task_id": task_id, "user_id": user["id"],
            "host": task["server_ip"], "port": task["ssh_port"],
        }.items()):
            raise HTTPException(409, "指纹确认不属于当前账号或任务，请重新核实。")
        stored, observed = preview.get("stored_keys"), preview.get("observed_key")
        if not isinstance(stored, list) or not stored or not all(isinstance(key, str) for key in stored) or not isinstance(observed, str) or observed in stored:
            raise HTTPException(409, "无效的指纹确认，请重新核实。")
        try:
            fresh = await probe_host_key(task["server_ip"], task["ssh_port"])
            if not secrets.compare_digest(fresh, observed):
                raise HTTPException(409, "服务器指纹在核实后再次变化，本次未更新；请重新核实。")
            old_fingerprints = "、".join(key_summary(key)["fingerprint"] for key in stored)
            role_label = "管理员" if user["role"] == "admin" else "客户"
            message = f"{role_label} {user['username']} 已确认并更新 {task['server_ip']}:{task['ssh_port']} 的 SSH 指纹：{old_fingerprints} → {key_summary(observed)['fingerprint']}。请重新输入 SSH 密码重试任务。"
            warning = store.update_host_key(task_id, message, lambda: replace_host_key(
                settings.data_dir / "ssh" / "known_hosts", task["server_ip"], task["ssh_port"], stored, observed))
        except (RemoteJobError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from None
        return {"message": "已更新此服务器的 SSH 指纹。" + (warning or "请在下方重新输入 SSH 密码并重试任务。")}

    @app.post("/api/tasks", status_code=201)
    async def new_task(request: Request):
        from app.migration import validate_database

        csrf(request)
        user = current(request)
        require_execution()
        task_id = uuid.uuid4().hex
        upload_path = None
        persisted = False
        form = await request.form(max_files=1, max_fields=20, max_part_size=65536)
        try:
            def field(name: str, default: str = "") -> str:
                value = form.get(name, default)
                if not isinstance(value, str):
                    raise ValueError(f"字段 {name} 格式错误。")
                return value

            def checkbox(name: str) -> bool:
                return field(name).lower() in {"true", "1", "on", "yes"}

            kind = field("kind")
            version = field("version")
            source_version = field("source_version") if kind == "migrate" else None
            if kind not in {"install", "migrate"} or version not in VERSIONS:
                raise ValueError("只支持搭建/迁移及 2.9.4、3.4.2 两个版本。")
            if kind == "migrate" and (source_version not in VERSIONS or source_version != version):
                raise ValueError("第一版只支持同版本数据库迁移，请选择与原面板相同的目标版本。")
            username = field("ssh_username", "root").strip()
            if username != "root":
                raise ValueError("第一版需要 root SSH 账号。")
            password = field("ssh_password")
            if not 1 <= len(password) <= 1024:
                raise ValueError("请填写有效的 SSH 密码。")
            ssh_port = int(field("ssh_port", "22"))
            if not 1 <= ssh_port <= 65535:
                raise ValueError("SSH 端口须为 1–65535。")
            custom_panel_port = checkbox("custom_panel_port")
            if custom_panel_port:
                try:
                    panel_port = int(field("panel_port"))
                except ValueError:
                    raise ValueError("勾选自定义端口后，请填写有效的面板端口。") from None
                check_panel_port(panel_port, ssh_port)
            else:
                panel_port = random_panel_port(ssh_port)
            values = {
                "id": task_id, "user_id": user["id"], "kind": kind,
                "server_ip": validate_target(field("server_ip"), settings.allow_private_targets),
                "ssh_port": ssh_port, "ssh_username": username,
                "domain": validate_domain(field("domain")), "version": version,
                "panel_port": panel_port, "custom_panel_port": custom_panel_port, "panel_path": "/" + secrets.token_urlsafe(24) + "/",
                "source_version": source_version, "overwrite_existing": checkbox("overwrite_existing"),
                "reset_two_factor": False,
                "encrypted_password": box.encrypt(password.encode()).decode(),
                "upload_path": None, "validation": None,
            }
            upload = form.get("database")
            if kind == "migrate":
                if not isinstance(upload, UploadFile) or not upload.filename or not upload.filename.lower().endswith(".db"):
                    raise ValueError("迁移需要上传从旧面板导出的 .db 数据库文件。")
                upload_path = upload_dir / f"{task_id}.db"
                length = 0
                with upload_path.open("xb") as output:
                    upload_path.chmod(0o600)
                    while chunk := await upload.read(1024 * 1024):
                        length += len(chunk)
                        if length > MAX_UPLOAD:
                            raise ValueError("数据库文件不能超过 50 MiB。")
                        output.write(chunk)
                validation = await asyncio.to_thread(validate_database, upload_path, source_version, version)
                original_port = validation["panel_settings"]["port"]
                try:
                    check_panel_port(original_port, ssh_port)
                except ValueError as exc:
                    raise ValueError(f"旧数据库中的面板端口 {original_port} 无法用于目标服务器：{exc}") from None
                if not custom_panel_port:
                    values["panel_port"] = random_panel_port(ssh_port, [original_port, *validation.get("inbound_ports", [])])
                values["upload_path"] = str(upload_path)
                values["validation"] = json.dumps(validation, ensure_ascii=False)
            task = store.create_task(values)
            persisted = True
            execution = execution_status()
            return {"task": task_response(task, execution), "execution": execution}
        except sqlite3.IntegrityError:
            if upload_path:
                upload_path.unlink(missing_ok=True)
            raise HTTPException(409, "同一服务器已有等待中或执行中的任务，请等待完成。") from None
        except (ValueError, sqlite3.DatabaseError) as exc:
            if upload_path:
                upload_path.unlink(missing_ok=True)
            raise HTTPException(422, str(exc)) from None
        finally:
            if upload_path and not persisted:
                upload_path.unlink(missing_ok=True)
            await form.close()

    @app.post("/api/tasks/{task_id}/retry", status_code=201)
    async def retry_task(request: Request, task_id: str, data: RetryInput):
        from app.migration import validate_database

        csrf(request)
        old = get_task(request, task_id)
        require_execution()
        if old["status"] not in {"failed", "interrupted"}:
            raise HTTPException(409, "只能重试失败或中断的任务。")
        new_id = uuid.uuid4().hex
        path = None
        validation = old["validation"]
        if old["kind"] == "migrate":
            if not old["upload_path"] or not Path(old["upload_path"]).is_file():
                raise HTTPException(410, "上传数据库已清理，请新建迁移任务并重新上传。")
            try:
                validation = await asyncio.to_thread(validate_database, Path(old["upload_path"]), old["source_version"], old["version"])
                check_panel_port(validation["panel_settings"]["port"], old["ssh_port"])
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
            path = upload_dir / f"{new_id}.db"
            shutil.copyfile(old["upload_path"], path)
            path.chmod(0o600)
        keys = ("user_id", "kind", "server_ip", "ssh_port", "ssh_username", "domain", "version", "panel_port", "custom_panel_port", "panel_path", "source_version", "overwrite_existing", "reset_two_factor")
        values = {key: old[key] for key in keys}
        if old["kind"] == "migrate":
            values["reset_two_factor"] = False
        values.update(id=new_id, encrypted_password=box.encrypt(data.ssh_password.encode()).decode(), upload_path=str(path) if path else None, validation=json.dumps(validation, ensure_ascii=False) if validation else None)
        try:
            task = store.create_task(values)
        except sqlite3.IntegrityError:
            if path:
                path.unlink(missing_ok=True)
            raise HTTPException(409, "该服务器已有执行中的任务。") from None
        execution = execution_status()
        return {"task": task_response(task, execution), "execution": execution}

    return app

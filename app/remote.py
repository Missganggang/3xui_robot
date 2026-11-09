"""Bounded SSH provisioning for the supported root/systemd installations.

No shell output is published: installers and restored databases can contain
credentials. HTTP probes connect to the validated IP with the customer's Host
and TLS SNI, so a DNS change cannot redirect a worker into an internal network.
"""

from __future__ import annotations

import asyncio
import base64
from contextlib import closing
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import sqlite3
import time
from typing import Awaitable, Callable

import asyncssh
import httpx

from .migration import backup_remote, import_remote_database, normalize_panel_path, rollback_remote
from .public_dns import resolve_public_dns


class RemoteJobError(RuntimeError):
    """An actionable, customer-safe error (never contains raw SSH output)."""


@dataclass(frozen=True)
class RemoteOptions:
    known_hosts_path: Path
    allow_private_targets: bool = False
    command_timeout: int = 900


INSTALLER_SHA256 = {
    "v2.9.4": "243e839e44d006644a87bbbc0a31b04fb51c8509ca841dc2dfbe1a37230de1bd",
    "v3.4.2": "bd1e19b674526c3e1fb7944500fef81e1e049e5c1db2ae7bbfa9a15b05667a1b",
}
MAX_INSTALLER_BYTES = 256 * 1024
CANCEL_GRACE_SECONDS = 2
BBR_CONFIG = "/etc/sysctl.d/99-zzz-3xui-web-bbr.conf"
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_PATH = re.compile(r"/[A-Za-z0-9_-]{8,80}/\Z")
_JOB = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")


def _validate_job(job: dict, options: RemoteOptions) -> dict:
    result = dict(job)
    try:
        address = ipaddress.ip_address(str(job["server_ip"]))
        port = int(job["panel_port"])
        ssh_port = int(job["ssh_port"])
    except (KeyError, ValueError, TypeError) as exc:
        raise RemoteJobError("服务器 IP 或端口无效。") from exc
    if not options.allow_private_targets and not address.is_global:
        raise RemoteJobError("此站点只允许连接公网服务器 IP。")
    if not 1 <= port <= 65535 or port == 80 or not 1 <= ssh_port <= 65535 or port == ssh_port:
        raise RemoteJobError("面板端口必须为 1–65535，且不能使用 80 或 SSH 端口。")
    version = "v" + str(job.get("version", "")).removeprefix("v")
    if version not in INSTALLER_SHA256 or job.get("kind") not in {"install", "migrate"}:
        raise RemoteJobError("任务类型或版本不受支持。")
    if job.get("ssh_username") != "root":
        raise RemoteJobError("首版仅支持使用 root 账号的 Ubuntu / Debian。")
    domain = str(job.get("domain", "")).lower().rstrip(".")
    if not _DOMAIN.fullmatch(domain) or not _PATH.fullmatch(str(job.get("panel_path", ""))):
        raise RemoteJobError("域名或面板入口路径无效。")
    if not _JOB.fullmatch(str(job.get("id", ""))):
        raise RemoteJobError("任务编号无效。")
    if job["kind"] == "migrate" and str(job.get("source_version", "")).removeprefix("v") != version[1:]:
        raise RemoteJobError("首版仅支持同版本迁移。")
    result.update(server_ip=str(address), panel_port=port, ssh_port=ssh_port, version=version, domain=domain)
    return result


def _record_host_key(path: Path, host: str, port: int, key: asyncssh.SSHKey) -> bool:
    """Legacy pin-check helper retained for manual maintenance compatibility.

    Runtime handshakes use host_keys.remember_host_key to record and update the
    observed key automatically under the same application-owned file lock.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RemoteJobError("SSH 指纹库正忙，请稍后重试。") from exc
    try:
        os.close(descriptor)
        identity = f"[{host}]:{port}"
        public_key = key.export_public_key("openssh").decode("ascii").strip()
        entries = path.read_text("ascii").splitlines() if path.exists() else []
        found = [line.split(maxsplit=1)[1] for line in entries if line.startswith(identity + " ")]
        if found:
            return len(found) == 1 and secrets.compare_digest(found[0], public_key)
        with path.open("a", encoding="ascii", newline="\n") as output:
            output.write(identity + " " + public_key + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
        return True
    finally:
        lock.unlink(missing_ok=True)


class _PinnedClient(asyncssh.SSHClient):
    def __init__(self, path: Path):
        self.path = path
        self.error: str | None = None
        self.host_key_updates: list[dict] = []

    def validate_host_public_key(self, host: str, addr: str, port: int, key: asyncssh.SSHKey) -> bool:
        # host_keys imports RemoteJobError, so load this only when handshaking.
        from .host_keys import remember_host_key

        try:
            update = remember_host_key(self.path, addr, port, key)
            if update["changed"] or update.get("warning"):
                self.host_key_updates.append(update)
            return True
        except RemoteJobError as exc:
            self.error = str(exc)
            return False
        except OSError:
            self.error = "无法安全保存或读取服务器 SSH 指纹，请管理员检查指纹库。"
            return False


async def _connect(job: dict, password: str, options: RemoteOptions,
                   emit: Callable[[str, str], Awaitable[None]] | None = None):
    client = _PinnedClient(options.known_hosts_path)
    connection = None
    try:
        try:
            connection = await asyncssh.connect(
                job["server_ip"], port=job["ssh_port"], username="root", password=password,
                known_hosts=b"", client_factory=lambda: client, config=None,
                client_keys=[], agent_path=None, preferred_auth=["password", "keyboard-interactive"],
                connect_timeout=20, login_timeout=30, keepalive_interval=15, keepalive_count_max=3,
            )
        except asyncssh.PermissionDenied as exc:
            raise RemoteJobError("SSH 登录失败，请核对 root 密码及密码登录设置。") from exc
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            raise RemoteJobError(client.error or "无法建立 SSH 连接，请核对 IP、端口、安全组及 SSH 服务。") from exc
        finally:
            if emit is not None:
                for update in client.host_key_updates:
                    messages = []
                    if update["changed"]:
                        old = "、".join(update["old_fingerprints"])
                        messages.append(f"服务器 {job['server_ip']}:{job['ssh_port']} 的 SSH 指纹已变化，系统已自动确认并更新：{old} → {update['new_fingerprint']}；本次任务无需客户确认指纹。")
                    if update.get("warning"):
                        messages.append(update["warning"])
                    try:
                        await emit("connect", " ".join(messages))
                    except Exception as exc:
                        raise RemoteJobError("SSH 指纹已自动更新，但无法保存任务日志，请稍后重试。") from exc
        return connection
    except BaseException:
        if connection is not None:
            await _close_connection(connection, time.monotonic() + 2)
        raise


async def _run(conn, command: str, timeout: int = 120, message: str = "远程步骤执行失败。") -> str:
    try:
        result = await conn.run(command, check=True, timeout=timeout)
        return result.stdout or ""
    except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
        raise RemoteJobError(message) from exc


def _python(code: str) -> str:
    return "python3 -c " + shlex.quote(code)


async def _check_dns(job: dict, options: RemoteOptions,
                     emit: Callable[[str, str], Awaitable[None]] | None = None) -> None:
    domain = job["domain"]
    target = ipaddress.ip_address(job["server_ip"])
    addresses = set()
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            domain, None, type=socket.SOCK_STREAM), 15)
        addresses = {ipaddress.ip_address(item[4][0]) for item in infos}
        local_result = "、".join(sorted(str(ip) for ip in addresses)) or "无 A / AAAA 地址"
    except asyncio.TimeoutError:
        local_result = "解析超时（15 秒）"
    except OSError:
        local_result = "解析失败"
    if addresses == {target} and (target.is_global or options.allow_private_targets):
        if emit is not None:
            await emit("dns", f"域名 {domain}；目标 IP {target}；本机 DNS：{local_result}。")
        return

    # The OS/network resolver may retain the old record after a DNS change.
    # Require two independent HTTPS resolvers' complete A + AAAA results before
    # accepting this fallback. Remote operations still connect to the pinned IP.
    if emit is not None:
        await emit("dns", f"域名 {domain}；目标 IP {target}；本机 DNS：{local_result}，与目标不符。正在向 AliDNS 和 DNSPod 核对完整 A / AAAA 解析（最多 10 秒）。")
    public_results = await resolve_public_dns(domain)
    evidence = []
    verified = []
    has_error = len(public_results) != 2
    for result in public_results:
        source = result["source"]
        if result.get("error"):
            evidence.append(f"{source}：{result['error']}")
            has_error = True
            continue
        resolved = {ipaddress.ip_address(ip) for ip in result["addresses"]}
        verified.append(resolved)
        evidence.append(f"{source}：" + ("、".join(sorted(str(ip) for ip in resolved)) or "无 A / AAAA 地址"))
    details = f"域名 {domain}；目标 IP {target}；本机 DNS：{local_result}；" + "；".join(evidence) + "。"
    if not has_error and len(verified) == 2 and all(
        resolved == {target} and (target.is_global or options.allow_private_targets)
        for resolved in verified
    ):
        if emit is not None:
            await emit("dns", details + "两家公网 DNS 的 A / AAAA 均仅指向目标服务器，已通过公网核验；本机 DNS 可能仍有旧缓存。")
        return

    if has_error:
        reason = "公网 DNS 核验未完成，请稍后重试；本次尚未连接或修改服务器。"
    elif any(not ip.is_global for resolved in verified for ip in resolved) and not options.allow_private_targets:
        reason = "域名 DNS 含内网或保留地址，要求所有解析只指向目标公网 IP。"
    elif any(target not in resolved for resolved in verified):
        reason = "公网 DNS 尚未一致指向目标公网 IP。"
    else:
        reason = "域名存在指向其他 IP 的 A / AAAA 记录，要求所有解析只指向当前服务器 IP。"
    raise RemoteJobError(details + reason + "请核对本任务的域名、A / AAAA 记录和 Cloudflare 代理状态（需仅 DNS/灰云）；若刚修改，请等待公网 DNS 更新后重试。")


_PREFLIGHT = r'''
import json, os, pathlib, re, shutil, subprocess
if os.geteuid() != 0:
    raise SystemExit('root required')
release = {}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1); release[key] = value.strip('"')
if release.get('ID') not in ('ubuntu', 'debian'):
    raise SystemExit('Ubuntu / Debian required')
if not pathlib.Path('/run/systemd/system').exists():
    raise SystemExit('systemd required')
import platform
arch = platform.machine()
if arch not in ('x86_64', 'aarch64', 'arm64', 'amd64'):
    raise SystemExit('amd64 / arm64 required')
if shutil.disk_usage('/').free < 1073741824:
    raise SystemExit('At least 1 GiB free disk required')
if shutil.which('modprobe'):
    subprocess.run(['modprobe', 'tcp_bbr'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
available = subprocess.check_output(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'], text=True).split()
if 'bbr' not in available:
    raise SystemExit('BBR-capable kernel required')
if pathlib.Path('/etc/x-ui').is_symlink() or pathlib.Path('/usr/local/x-ui').is_symlink():
    raise SystemExit('Nonstandard symlink installation unsupported')
exists = any(pathlib.Path(p).exists() for p in ('/usr/local/x-ui/x-ui', '/etc/x-ui/x-ui.db', '/etc/systemd/system/x-ui.service'))
if exists:
    data = subprocess.run(['systemctl', 'show', 'x-ui', '-p', 'User', '-p', 'ExecStart', '-p', 'Environment'], capture_output=True, text=True, timeout=20).stdout
    if any(line.startswith('User=') and line not in ('User=', 'User=root') for line in data.splitlines()):
        raise SystemExit('Service must run as root')
    if 'ExecStart=' in data and not re.search(r'path=/usr/local/x-ui/x-ui(?:\s|;)', data):
        raise SystemExit('Nonstandard ExecStart unsupported')
    for path in ('/etc/default/x-ui', '/etc/systemd/system/x-ui.service', '/etc/systemd/system/x-ui.service.d'):
        p = pathlib.Path(path)
        files = list(p.glob('*.conf')) if p.is_dir() else ([p] if p.exists() else [])
        for f in files:
            text = f.read_text(errors='replace')
            if 'XUI_DB_FOLDER' in text or 'XUI_DB_TYPE=postgres' in text or 'XUI_DB_DSN' in text:
                raise SystemExit('Only default SQLite installation supported')
            for line in text.splitlines():
                if line.strip().startswith('EnvironmentFile=') and line.strip() not in ('EnvironmentFile=/etc/default/x-ui', 'EnvironmentFile=-/etc/default/x-ui'):
                    raise SystemExit('Custom service environment file unsupported')
    if 'XUI_DB_FOLDER' in data or 'XUI_DB_TYPE=postgres' in data or 'XUI_DB_DSN' in data:
        raise SystemExit('Only default SQLite installation supported')
managed_job = None
metadata = pathlib.Path('/etc/x-ui/web-automation.json')
if metadata.is_file() and metadata.stat().st_size < 4096:
    try: managed_job = json.loads(metadata.read_text()).get('job_id')
    except (ValueError, OSError): pass
print(json.dumps({'existing': exists, 'os': release['ID'], 'arch': arch, 'managed_job': managed_job}))
'''


async def _probe_port(conn, job: dict, port: int) -> None:
    token = secrets.token_urlsafe(24)
    path = "/.well-known/acme-challenge/3xui-" + token
    family = "socket.AF_INET6" if ":" in job["server_ip"] else "socket.AF_INET"
    address = "::" if ":" in job["server_ip"] else "0.0.0.0"
    code = f'''
import http.server, socket, time
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != {path!r}: self.send_error(404); return
        self.send_response(200); self.end_headers(); self.wfile.write({token.encode()!r}); self.server.verified = True
    def log_message(self, *args): pass
class Server(http.server.HTTPServer): address_family = {family}
server = Server(({address!r}, {port}), Handler)
server.timeout = 2
server.verified = False
deadline = time.monotonic() + 25
print('READY', flush=True)
while not server.verified and time.monotonic() < deadline:
    server.handle_request()
server.server_close()
'''
    process = None
    try:
        process = await conn.create_process(_python(code))
        ready = await asyncio.wait_for(process.stdout.readline(), 10)
        if ready.strip() != "READY":
            raise RemoteJobError(f"服务器 {port} 端口已被占用或无法监听，请先处理端口冲突。")
        host = f"[{job['server_ip']}]" if ":" in job["server_ip"] else job["server_ip"]
        async with httpx.AsyncClient(timeout=15, trust_env=False, follow_redirects=False) as client:
            response = await client.get(f"http://{host}:{port}{path}", headers={"Host": job["domain"]})
        if response.status_code != 200 or response.text != token:
            raise RemoteJobError(f"公网无法验证服务器 {port} 端口，请检查防火墙和云安全组。")
    except (httpx.HTTPError, asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
        raise RemoteJobError(f"公网无法访问服务器 {port} 端口，请放行防火墙和云安全组后重试。") from exc
    finally:
        if process is not None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait_closed(), 5)
            except (asyncssh.Error, OSError, asyncio.TimeoutError):
                pass


def _prepare_installer(source: bytes, version: str) -> tuple[bytes, str]:
    digest = hashlib.sha256(source).hexdigest()
    if digest != INSTALLER_SHA256[version]:
        raise RemoteJobError("官方安装脚本内容与已核验版本不一致，已停止；请管理员核查更新。")
    text = source.decode("utf-8")
    marker = "    config_after_install\n"
    if text.count(marker) != 1:
        raise RemoteJobError("安装脚本结构发生变化，无法安全使用无人值守安装。")
    # Both tags configure panel options interactively here. We retain the
    # official installation and replace only this one call with noninteractive
    # database initialization, then apply target settings ourselves.
    text = text.replace(marker, '    "${xui_folder}/x-ui" migrate\n')
    start_marker = "            systemctl start x-ui\n"
    if text.count(start_marker) != 1:
        raise RemoteJobError("安装脚本启动步骤发生变化，无法保证配置前面板保持关闭。")
    text = text.replace(start_marker, "            : # start only after target settings and TLS are ready\n")
    text = text.replace("https://raw.githubusercontent.com/MHSanaei/3x-ui/main/",
                        f"https://raw.githubusercontent.com/MHSanaei/3x-ui/{version}/")
    return text.encode("utf-8"), digest


async def _download_installer(conn, version: str) -> bytes:
    """Fetch over the existing SSH connection, with limits on both endpoints."""
    if version not in INSTALLER_SHA256:
        raise RemoteJobError("指定版本不受支持，无法下载官方安装脚本。")
    url = f"https://raw.githubusercontent.com/mhsanaei/3x-ui/{version}/install.sh"
    code = f'''
import base64, urllib.request
request = urllib.request.Request({url!r}, headers={{'User-Agent': '3xui-web-provisioner'}})
try:
    with urllib.request.urlopen(request, timeout=45) as response:
        source = response.read({MAX_INSTALLER_BYTES + 1})
except Exception:
    raise SystemExit('Unable to download official installer')
if len(source) > {MAX_INSTALLER_BYTES}:
    print('INSTALLER_TOO_LARGE', flush=True)
else:
    print(base64.b64encode(source).decode('ascii'), flush=True)
'''
    encoded = (await _run(
        conn, _python(code), timeout=60,
        message="目标服务器无法下载官方安装脚本，请检查目标服务器访问 GitHub 的网络后重试。",
    )).strip()
    if encoded == "INSTALLER_TOO_LARGE" or len(encoded) > ((MAX_INSTALLER_BYTES + 2) // 3) * 4:
        raise RemoteJobError("目标服务器下载的官方安装脚本体积异常，已停止。")
    try:
        source = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise RemoteJobError("目标服务器返回的官方安装脚本数据无效，已停止。") from exc
    if not source or len(source) > MAX_INSTALLER_BYTES:
        raise RemoteJobError("目标服务器下载的官方安装脚本体积异常，已停止。")
    return source


async def _install(conn, job: dict, options: RemoteOptions, emit) -> None:
    version = job["version"]
    await emit("download", f"正在通过 SSH 让目标服务器下载 {version[1:]} 官方安装脚本，并检查完整性。")
    source = await _download_installer(conn, version)
    script, digest = _prepare_installer(source, version)
    await emit("download", f"官方安装脚本下载与完整性检查已通过（SHA-256 {digest}）。")
    encoded = base64.b64encode(script).decode("ascii")
    folder = "/root/.3xui-web-tasks/" + job["id"]
    command = (
        "umask 077; mkdir -p " + shlex.quote(folder) + " && "
        "printf %s " + shlex.quote(encoded) + " | base64 -d > " + shlex.quote(folder + "/install.sh")
        + " && DEBIAN_FRONTEND=noninteractive XUI_NONINTERACTIVE=1 XUI_ENABLE_FAIL2BAN=false "
        + "bash " + shlex.quote(folder + "/install.sh") + " " + shlex.quote(version) + " </dev/null"
    )
    await emit("install", f"正在安装 {version[1:]}：服务器将下载发布包、安装系统依赖并初始化数据库，此步骤可能需要数分钟。")
    await _run(conn, command, options.command_timeout, "3x-ui 安装失败或超时；请检查服务器访问 GitHub 和软件源的网络。")
    await emit("install", "官方安装步骤已结束，正在检查安装后的面板版本。")
    await _run(conn, "systemctl stop x-ui", message="无法停止新面板服务以安全配置。")
    version_output = await _run(conn, "/usr/local/x-ui/x-ui -v")
    if not re.search(r"(?<![\d.])" + re.escape(version[1:]) + r"(?![\d.])", version_output):
        raise RemoteJobError("安装后的面板版本与所选版本不一致。")
    await emit("install", f"安装与版本检查已通过，当前面板版本为 {version[1:]}。")


async def _configure(conn, job: dict) -> None:
    reset = " -resetTwoFactor=true" if job.get("reset_two_factor") else ""
    command = (
        "/usr/local/x-ui/x-ui setting -username qqqzzz -password qqqzzz"
        + f" -port {job['panel_port']} -webBasePath " + shlex.quote(job["panel_path"])
        + " -listenIP " + shlex.quote(job.get("listen_ip") or ("::" if ":" in job["server_ip"] else "0.0.0.0")) + reset
    )
    await _run(conn, command, message="无法写入目标面板账号、端口或入口路径。")
    code = f'''
import sqlite3
with sqlite3.connect('/etc/x-ui/x-ui.db', timeout=20) as db:
    row = db.execute('SELECT id FROM settings WHERE key=?', ('webDomain',)).fetchone()
    if row: db.execute('UPDATE settings SET value=? WHERE key=?', ({job['domain']!r}, 'webDomain'))
    else: db.execute('INSERT INTO settings (key, value) VALUES (?, ?)', ('webDomain', {job['domain']!r}))
'''
    await _run(conn, _python(code), message="无法绑定目标面板域名。")


async def _configure_restored(conn, job: dict) -> None:
    """Adapt the new host without writing restored credentials, port or path."""
    listen_ip = "::" if ":" in job["server_ip"] else "0.0.0.0"
    await _run(conn, "/usr/local/x-ui/x-ui setting -listenIP " + shlex.quote(listen_ip),
               message="无法适配迁移后的面板监听地址。")
    code = f'''
import sqlite3
with sqlite3.connect('/etc/x-ui/x-ui.db', timeout=20) as db:
    if db.execute('SELECT 1 FROM settings WHERE key=?', ('webDomain',)).fetchone():
        db.execute('UPDATE settings SET value=? WHERE key=?', ({job['domain']!r}, 'webDomain'))
    else:
        db.execute('INSERT INTO settings (key, value) VALUES (?, ?)', ('webDomain', {job['domain']!r}))
'''
    await _run(conn, _python(code), message="无法将迁移后的面板绑定到新域名。")


_PRESERVED_STATE_CODE = r'''
import base64, hashlib, json, sqlite3
def preserved_database_state(db, columns):
    names = ','.join('"' + name.replace('"', '""') + '"' for name in columns)
    users = [list(row) for row in db.execute('SELECT ' + names + ' FROM users')]
    def encode(value):
        if isinstance(value, bytes): return {'bytes': base64.b64encode(value).decode('ascii')}
        raise TypeError('Unsupported account value')
    rows = sorted(json.dumps(row, ensure_ascii=True, separators=(',', ':'), default=encode) for row in users)
    factors = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('twoFactorEnable','twoFactorToken')"))
    protected = {'columns': columns, 'users': rows,
                 'two_factor': [str(factors.get('twoFactorEnable', 'false')).lower(), factors.get('twoFactorToken', '')]}
    encoded = json.dumps(protected, ensure_ascii=True, sort_keys=True, separators=(',', ':'), default=encode)
    values = dict(db.execute("SELECT key,value FROM settings WHERE key IN ('webPort','webBasePath')"))
    port = values.get('webPort', '2053')
    if port == '' and SOURCE_VERSION == 'v3.4.2': port = '2053'
    inbound_columns = {row[1] for row in db.execute('PRAGMA table_info(inbounds)')}
    ports = sorted(int(row[0]) for row in db.execute('SELECT port FROM inbounds')) if 'port' in inbound_columns else []
    return {'credentials_digest': hashlib.sha256(encoded.encode('utf-8')).hexdigest(),
            'port': int(port), 'path': values.get('webBasePath', '/'), 'inbound_ports': ports}
'''


def _migration_context(job: dict, upload_path: Path) -> tuple[dict, dict]:
    """Derive final access from the upload; protected digests stay in memory."""
    try:
        with closing(sqlite3.connect(upload_path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            columns = sorted(row[1] for row in db.execute("PRAGMA table_info(users)"))
            if not {"username", "password"}.issubset(columns):
                raise RemoteJobError("上传数据库缺少原面板账号，无法保留迁移。")
            namespace = {"SOURCE_VERSION": job["version"]}
            # Execute only our fixed helper, never SQL/code from the upload.
            exec(_PRESERVED_STATE_CODE, namespace)
            state = namespace["preserved_database_state"](db, columns)
        path = normalize_panel_path(state["path"])
        port = state["port"]
        if not 1 <= port <= 65535 or port in {80, 22, job["ssh_port"]}:
            raise RemoteJobError("原数据库的面板端口不能使用 80、22 或目标 SSH 端口；请先调整原面板后重新导出。")
        final_settings = {"port": port, "path": path}
        checked = (job.get("validation") or {}).get("panel_settings")
        if checked is not None and checked != final_settings:
            raise RemoteJobError("上传数据库的原面板设置与验收记录不一致，请重新提交备份。")
        final_job = {**job, "panel_port": port, "panel_path": path, "reset_two_factor": False}
        return final_job, {**state, "path": path, "user_columns": columns}
    except RemoteJobError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        raise RemoteJobError("无法读取原数据库的面板端口、入口路径或账号状态，请重新导出完整备份。") from exc


async def _verify_temporary_installation(conn, job: dict) -> None:
    code = f'''
import json, sqlite3
db=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
try:
    if db.execute('PRAGMA quick_check').fetchone() != ('ok',): raise RuntimeError('Invalid fresh database')
    values=dict(db.execute("SELECT key,value FROM settings WHERE key IN ('webPort','webBasePath')"))
    if int(values.get('webPort', '2053')) != {job['panel_port']}: raise RuntimeError('Temporary panel port mismatch')
    if not db.execute('SELECT count(*) FROM users').fetchone()[0]: raise RuntimeError('Fresh panel missing account')
    if db.execute('SELECT count(*) FROM inbounds').fetchone()[0]: raise RuntimeError('Fresh panel is not empty')
finally: db.close()
'''
    await _run(conn, _python(code), message="临时面板安装状态检查失败，尚未导入客户数据库。")


async def _verify_preserved_migration_state(conn, job: dict, original: dict) -> None:
    code = f"SOURCE_VERSION={job['version']!r}\n" + _PRESERVED_STATE_CODE + f'''
db=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
try:
    db.execute('PRAGMA trusted_schema=OFF')
    print(json.dumps(preserved_database_state(db, {original['user_columns']!r})))
finally: db.close()
'''
    actual = json.loads(await _run(conn, _python(code), message="无法核对迁移后的原账号、二次验证及面板设置。"))
    try:
        actual_path = normalize_panel_path(actual["path"])
        matches = (
            actual.get("credentials_digest") == original["credentials_digest"]
            and actual.get("port") == job["panel_port"]
            and actual_path == job["panel_path"]
            and actual.get("inbound_ports") == original["inbound_ports"]
        )
    except (KeyError, TypeError, ValueError):
        matches = False
    if not matches:
        raise RemoteJobError("迁移后的原账号、二次验证、端口、入口路径或入站端口发生变化，已停止交付。")


async def _verify_migration_counts(conn, job: dict) -> dict:
    expected = job.get("validation") or {}
    if not all(isinstance(expected.get(key), int) for key in ("inbounds", "clients")):
        raise RemoteJobError("缺少上传数据库的数据验收记录，不能标记迁移完成。")
    code = f'''
import json, sqlite3
db=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
try:
    inbounds=db.execute('SELECT count(*) FROM inbounds').fetchone()[0]
    if {job['version']!r} == 'v3.4.2':
        clients=db.execute('SELECT count(*) FROM clients').fetchone()[0]
    else:
        clients=0
        for row in db.execute('SELECT settings FROM inbounds'):
            clients += len(json.loads(row[0] or '{{}}').get('clients', []))
    print(json.dumps({{'inbounds': inbounds, 'clients': clients}}))
finally: db.close()
'''
    actual = json.loads(await _run(conn, _python(code), message="无法读取迁移后的入站和客户数量。"))
    if any(actual.get(key) != expected[key] for key in ("inbounds", "clients")):
        raise RemoteJobError("迁移后的入站或客户数量与上传数据库不一致，已停止完成验收。")
    return {key: actual[key] for key in ("inbounds", "clients")}


async def _issue_certificate(conn, job: dict, options: RemoteOptions) -> dict:
    home = "/root/.3xui-web-acme/" + job["id"]
    source_dir = "/root/.3xui-web-tasks/" + job["id"] + "/acme-source"
    cert_dir = "/root/cert/" + job["domain"]
    certificate_file, private_key_file = cert_dir + "/fullchain.pem", cert_dir + "/privkey.pem"
    cron = "/etc/cron.d/3xui-web-" + job["id"]
    qhome, qcert, qsource = shlex.quote(home), shlex.quote(cert_dir), shlex.quote(source_dir)
    prepare = f'''
from pathlib import Path
for directory in (Path('/root'), Path('/root/cert'), Path({cert_dir!r})):
    if directory.is_symlink() or directory.exists() and not directory.is_dir():
        raise RuntimeError('Unsafe certificate directory')
    directory.mkdir(mode=0o700, exist_ok=True)
for name in ('fullchain.pem', 'privkey.pem'):
    target = Path({cert_dir!r}) / name
    if target.is_symlink() or target.exists() and not target.is_file():
        raise RuntimeError('Unsafe certificate file')
Path({cert_dir!r}).chmod(0o700)
'''
    await _run(conn, _python(prepare), message="无法安全准备证书目录，请检查 /root/cert 下的目录及证书文件。")
    listener = " --listen-v6" if ":" in job["server_ip"] else ""
    command = f'''set -e
umask 077
mkdir -p {qhome} {qcert} {qsource}
curl -fsSL --connect-timeout 15 --max-time 120 https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o {qsource}/acme.sh
cd {qsource}
sh ./acme.sh --install --home {qhome} --nocron --noprofile
{qhome}/acme.sh --home {qhome} --set-default-ca --server letsencrypt
{qhome}/acme.sh --home {qhome} --issue --server letsencrypt --standalone --httpport 80 --keylength ec-256 -d {shlex.quote(job['domain'])}{listener}
{qhome}/acme.sh --home {qhome} --install-cert --ecc -d {shlex.quote(job['domain'])} --key-file {qcert}/privkey.pem --fullchain-file {qcert}/fullchain.pem --reloadcmd 'systemctl try-restart x-ui'
chmod 600 {qcert}/privkey.pem
/usr/local/x-ui/x-ui cert -webCert {qcert}/fullchain.pem -webCertKey {qcert}/privkey.pem
'''
    await _run(conn, command, options.command_timeout, "SSL 证书申请失败，请检查 DNS、80 端口及证书机构频率限制。")
    # Our dedicated ACME homes do not change any existing customer acme.sh job.
    cron_text = "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    cron_text += f"{secrets.randbelow(60)} 3 * * * root {home}/acme.sh --cron --home {home} >/dev/null 2>&1\n"
    await _run(conn, _python(
        "from pathlib import Path\n"
        f"p=Path({cron!r}); p.write_text({cron_text!r}); p.chmod(0o600)\n"
    ) + " && systemctl enable --now cron", message="无法设置 SSL 证书自动续期任务。")
    expiry = (await _run(conn, "openssl x509 -in " + qcert + "/fullchain.pem -noout -enddate")).strip().removeprefix("notAfter=")
    return {"status": "valid", "expires_at": expiry, "auto_renew": True,
            "certificate_file": certificate_file, "private_key_file": private_key_file}


async def _enable_bbr(conn) -> dict:
    config_text = "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"
    code = f'''
import base64, json, pathlib, shutil, subprocess
p=pathlib.Path({BBR_CONFIG!r})
if p.is_symlink(): raise SystemExit('Unsafe BBR config')
old={{'qdisc': subprocess.check_output(['sysctl','-n','net.core.default_qdisc'], text=True).strip(),
      'control': subprocess.check_output(['sysctl','-n','net.ipv4.tcp_congestion_control'], text=True).strip(),
      'file': base64.b64encode(p.read_bytes()).decode() if p.exists() else None}}
if shutil.which('modprobe'):
    subprocess.run(['modprobe','tcp_bbr'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
available=subprocess.check_output(['sysctl','-n','net.ipv4.tcp_available_congestion_control'],text=True).split()
if 'bbr' not in available: raise SystemExit('BBR unsupported by current kernel')
p.write_text({config_text!r})
p.chmod(0o644)
print(json.dumps(old),flush=True)
'''
    original = json.loads(await _run(conn, _python(code), message="当前内核不支持 BBR，或无法保存 BBR 配置。"))
    try:
        await _run(conn, "sysctl -p " + BBR_CONFIG, message="BBR 配置无法应用。")
        await _verify_bbr(conn)
    except Exception:
        await _restore_bbr(conn, original)
        raise
    return original


async def _verify_bbr(conn) -> None:
    actual = (await _run(conn, "sysctl -n net.ipv4.tcp_congestion_control")).strip()
    if actual != "bbr":
        raise RemoteJobError("BBR 验证失败，系统没有使用 bbr 算法。")


async def _restore_bbr(conn, state: dict) -> None:
    code = f'''
import base64,pathlib,subprocess
state={state!r}
p=pathlib.Path({BBR_CONFIG!r})
if state['file'] is None: p.unlink(missing_ok=True)
else: p.write_bytes(base64.b64decode(state['file'])); p.chmod(0o644)
subprocess.run(['sysctl','-w','net.core.default_qdisc='+state['qdisc']],check=True,capture_output=True)
subprocess.run(['sysctl','-w','net.ipv4.tcp_congestion_control='+state['control']],check=True,capture_output=True)
'''
    await _run(conn, _python(code), message="无法恢复原 BBR 参数，请管理员检查。")


async def _verify_https_login(job: dict) -> None:
    host = f"[{job['server_ip']}]" if ":" in job["server_ip"] else job["server_ip"]
    origin = f"https://{host}:{job['panel_port']}"
    host_header = job["domain"] + (f":{job['panel_port']}" if job["panel_port"] != 443 else "")
    try:
        async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as client:
            request = client.build_request("GET", origin + job["panel_path"], headers={"Host": host_header})
            request.extensions["sni_hostname"] = job["domain"]
            response = await client.send(request)
            if response.status_code != 200:
                raise RemoteJobError("面板 HTTPS 地址无法正常访问，请核对域名绑定和入口路径。")
            if job.get("kind") == "migrate":
                # Restored passwords are hashes, and the customer keeps the
                # original account and authenticator. Do not attempt a login.
                return
            login_headers = {"Host": host_header}
            if job["version"] == "v3.4.2":
                request = client.build_request("GET", origin + job["panel_path"] + "csrf-token",
                                               headers={"Host": host_header})
                request.extensions["sni_hostname"] = job["domain"]
                response = await client.send(request)
                payload = response.json()
                token = payload.get("obj") if isinstance(payload, dict) else None
                if response.status_code != 200 or not isinstance(payload, dict) or payload.get("success") is not True or not isinstance(token, str) or not 16 <= len(token) <= 256:
                    raise RemoteJobError("面板登录会话初始化失败，无法验证 3.4.2 账号。")
                login_headers["X-CSRF-Token"] = token
            request = client.build_request("POST", origin + job["panel_path"] + "login",
                                           headers=login_headers,
                                           data={"username": "qqqzzz", "password": "qqqzzz"})
            request.extensions["sni_hostname"] = job["domain"]
            response = await client.send(request)
            payload = response.json()
            if response.status_code != 200 or not isinstance(payload, dict) or payload.get("success") is not True:
                raise RemoteJobError("面板账号登录验收失败，任务不能标记完成。")
    except (httpx.HTTPError, ValueError) as exc:
        raise RemoteJobError("HTTPS 证书或面板连接验证失败，请检查域名证书和面板端口。") from exc


async def _wait_for_panel(job: dict, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            await _verify_https_login(job)
            return
        except RemoteJobError as exc:
            last_error = exc
            await asyncio.sleep(3)
    raise last_error or RemoteJobError("等待面板启动超时。")


async def _bounded_call(operation, deadline: float, limit: float):
    """Enforce a short operation budget without slow cancellation cleanup."""
    task = asyncio.ensure_future(operation)
    cleanup_timer = None
    def discard_result(finished):
        if cleanup_timer is not None:
            cleanup_timer.cancel()
        try:
            result = finished.result()
            # Do not leak a resource returned after the operation was cancelled.
            abort = getattr(result, "abort", None)
            if callable(abort):
                abort()
        except (Exception, asyncio.CancelledError):
            pass
    try:
        remaining = min(limit, deadline - time.monotonic())
        if remaining <= 0:
            raise asyncio.TimeoutError
        done, _ = await asyncio.wait({task}, timeout=remaining)
        if task in done:
            return task.result()
        raise asyncio.TimeoutError
    except BaseException:
        task.cancel()
        if not task.done():
            cleanup_timer = asyncio.get_running_loop().call_later(CANCEL_GRACE_SECONDS, task.cancel)
        task.add_done_callback(discard_result)
        raise


async def _close_connection(conn, deadline: float) -> None:
    """Best effort bounded connection close, tolerant of shutdown EOF."""
    try:
        conn.close()
        remaining = deadline - time.monotonic()
        if remaining > 0:
            await _bounded_call(conn.wait_closed(), deadline, 2)
            return
    except Exception:
        pass
    # abort() does not wait for another network exchange after budget expiry.
    abort = getattr(conn, "abort", None)
    if callable(abort):
        try:
            abort()
        except Exception:
            pass


async def _schedule_final_reboot(conn, job: dict) -> None:
    """This must be the last remote command after migration verification."""
    command = "systemd-run --unit=3xui-reboot-" + job["id"] + " --on-active=5s /sbin/reboot"
    await _bounded_call(
        _run(conn, command, timeout=15, message="服务器重启调度未得到确认。"),
        time.monotonic() + 15, 15,
    )


async def _remove_acme_job(conn, job: dict) -> None:
    # Only task-owned paths are removed. Existing customer acme.sh is untouched.
    command = "rm -f -- " + shlex.quote("/etc/cron.d/3xui-web-" + job["id"])
    command += " && rm -rf -- " + shlex.quote("/root/.3xui-web-acme/" + job["id"])
    await _run(conn, command)


async def _finalize_acme(conn, job: dict, previous_id: str | None) -> None:
    metadata = json.dumps({"job_id": job["id"], "domain": job["domain"]})
    code = "from pathlib import Path\n"
    code += "p=Path('/etc/x-ui/web-automation.json')\n"
    code += f"p.write_text({metadata!r}); p.chmod(0o600)\n"
    await _run(conn, _python(code))
    if isinstance(previous_id, str) and _JOB.fullmatch(previous_id) and previous_id != job["id"]:
        await _remove_acme_job(conn, {"id": previous_id})


async def run_remote_job(
    job: dict, ssh_password: str, upload_path: Path | None,
    emit: Callable[[str, str], Awaitable[None]], options: RemoteOptions,
) -> dict:
    job = _validate_job(job, options)
    phase_job, final_job = job, job
    preserved_state = None
    if job["kind"] == "migrate":
        if upload_path is None or not upload_path.is_file():
            raise RemoteJobError("迁移数据库文件不存在。")
        final_job, preserved_state = _migration_context(job, upload_path)
        # Temporary settings belong only to the fresh, stopped installation.
        # The customer's restored database supplies final port/path/credentials.
        phase_job = {**job, "kind": "install", "listen_ip": "127.0.0.1", "reset_two_factor": False}
    await emit("dns", "正在检查域名解析是否仅指向目标服务器。")
    await _check_dns(job, options, emit)
    await emit("dns", "域名解析检查已通过。")
    await emit("connect", f"正在连接目标服务器 SSH，端口 {job['ssh_port']}。")
    conn = await _connect(job, ssh_password, options, emit)
    backup_path = None
    bbr_state = None
    acme_started = False
    migration_counts = None
    warnings = []
    try:
        warnings.extend((job.get("validation") or {}).get("warnings", []))
        await emit("connect", "SSH 连接与服务器指纹检查已通过。")
        await emit("preflight", "正在检查服务器系统、权限、磁盘空间、BBR 支持及现有面板配置。")
        preflight = json.loads(await _run(conn, _python(_PREFLIGHT), message="服务器环境不符合要求：需 root、Ubuntu / Debian、python3、systemd、amd64/arm64、至少 1 GiB 空间、BBR 内核及默认 SQLite 安装。"))
        if preflight["existing"] and not job.get("overwrite_existing"):
            raise RemoteJobError("目标服务器已有面板或数据库，需明确勾选允许覆盖并备份后再提交。")
        await emit("preflight", "服务器环境检查已通过。")
        await emit("ports", "正在检测公网 80 端口是否可用于 SSL 证书验证。")
        await _probe_port(conn, job, 80)
        await emit("ports", "公网 80 端口检查已通过。")
        await emit("backup", "正在停止面板并保存可回滚备份。")
        backup_path = await backup_remote(conn, job["id"], cert_domain=job["domain"])
        await emit("backup", f"备份已完成：{backup_path}")
        await emit("ports", f"正在检测最终面板端口 {final_job['panel_port']} 是否可监听并从公网访问。")
        await _probe_port(conn, final_job, final_job["panel_port"])
        await emit("ports", f"最终面板端口 {final_job['panel_port']} 检查已通过。")
        # A checked, complete snapshot now exists. Start from a clean database
        # for both paths; migration replaces it with the validated source later.
        await _run(conn, "rm -f -- /etc/x-ui/x-ui.db /etc/x-ui/x-ui.db-wal /etc/x-ui/x-ui.db-shm",
                   message="无法清理已备份的旧数据库。")
        await _install(conn, phase_job, options, emit)
        if job["kind"] == "migrate":
            await emit("configure", "正在初始化临时面板配置；保持服务关闭，临时端口无需公网放行。")
            await _configure(conn, phase_job)
            await _verify_temporary_installation(conn, phase_job)
            await emit("install", "临时面板安装与空数据库检查已通过，开始导入原面板数据库。")
            await emit("import", "正在校验并原子替换数据库，旧数据保留在服务器备份目录。")
            imported = await import_remote_database(conn, upload_path, backup_path, job["id"])
            expected_inbounds = (job.get("validation") or {}).get("inbounds")
            if not isinstance(expected_inbounds, int) or imported.get("inbounds") != expected_inbounds:
                raise RemoteJobError("导入后的入站数量与上传数据库不一致，已停止迁移。")
            warnings.extend(imported.get("warnings", []))
            await emit("import", "数据库上传校验与原子替换已完成，入站数量检查已通过。")
            await emit("configure", f"沿用原数据库端口 {final_job['panel_port']} 和入口路径，正在适配新域名与监听地址；保留全部原账号和二次验证。")
            await _configure_restored(conn, final_job)
            await emit("configure", "新域名与监听地址适配已完成，未重设原账号、二次验证、面板端口或入口路径。")
            migration_counts = await _verify_migration_counts(conn, final_job)
            await emit("verify", f"数据库已核对：{migration_counts['inbounds']} 条入站，{migration_counts['clients']} 条客户记录。")
        else:
            await emit("configure", "正在设置域名、面板入口及指定的面板账号。")
            await _configure(conn, final_job)
            await emit("configure", "域名、面板入口与账号设置已完成。")
        await emit("certificate", "正在申请 SSL 证书并设置自动续期。")
        acme_started = True
        certificate = await _issue_certificate(conn, final_job, options)
        await emit("certificate", f"SSL 证书已保存到 /root/cert/{job['domain']}/，面板绑定及自动续期设置已完成。")
        if preserved_state is not None:
            await _verify_preserved_migration_state(conn, final_job, preserved_state)
            await emit("verify", "原账号、二次验证、面板端口、入口路径与全部入站端口保留检查已通过。")
        await emit("bbr", "正在检查内核并启用 BBR。")
        bbr_state = await _enable_bbr(conn)
        await emit("bbr", "BBR 已启用，当前拥塞控制算法检查已通过。")
        await emit("restart", "正在启用面板开机启动并启动面板服务。")
        await _run(conn, "systemctl enable x-ui && systemctl restart x-ui", message="面板服务启动失败。")
        await emit("restart", "面板服务启动命令已完成，开始检查实际访问结果。")
        await emit("verify", "正在验证最终 HTTPS 证书与访问地址。" if preserved_state is not None else "正在验证 HTTPS 证书、访问地址和账号登录。")
        await _wait_for_panel(final_job)
        await emit("verify", "最终 HTTPS 证书与访问地址检查已通过；原账号和二次验证由客户自行登录。" if preserved_state is not None else "HTTPS 证书、访问地址及面板账号登录检查已通过。")
        await emit("cleanup", "正在确认本次自动续期配置并清理旧自动化证书任务。")
        try:
            await _finalize_acme(conn, final_job, preflight.get("managed_job"))
        except RemoteJobError:
            warnings.append("新证书续期已设置，但旧自动化证书任务清理失败，请管理员核对重复续期任务。")
            await emit("cleanup", "面板交付检查已通过；旧证书任务清理未完成，已记录提醒。")
        else:
            await emit("cleanup", "自动续期配置确认与旧任务清理已完成。")
        port_part = "" if final_job["panel_port"] == 443 else f":{final_job['panel_port']}"
        url = f"https://{final_job['domain']}{port_part}{final_job['panel_path']}"
        if preserved_state is not None:
            warnings.append("已保留原账号、密码和二次验证；网站未自动登录，请使用原账号及原验证器访问面板。")
        result = {
            "url": url, "panel_url": url,
            "version": job["version"][1:], "domain": job["domain"], "panel_port": final_job["panel_port"],
            "panel_path": final_job["panel_path"], "bbr": True, "certificate": certificate,
            "backup_path": backup_path, "warnings": list(dict.fromkeys(warnings)), "login_verified": preserved_state is None,
            "panel_access_verified": True, "credentials_preserved": preserved_state is not None,
            "migration_counts": migration_counts,
        }
        if preserved_state is None:
            result.update(username="qqqzzz", password="qqqzzz")
        else:
            result["temporary_panel_port"] = phase_job["panel_port"]
            result.update(reboot_scheduled=False, reboot_verified=False)
            # All migration work and verification is complete. Reboot scheduling
            # is deliberately outside the rollback boundary: an unconfirmed
            # acknowledgement must not restore an already migrated database.
            try:
                await emit("reboot", "迁移与重启前检查已完成，正在安排服务器约 5 秒后重启；本任务直接返回最终地址，不等待重启回连。")
            except Exception:
                pass
            try:
                await _schedule_final_reboot(conn, final_job)
                result["reboot_scheduled"] = True
                reboot_message = "迁移完成，服务器已安排约 5 秒后重启；未验证重启结果，稍后请使用原账号访问最终地址。"
            except Exception:
                reboot_message = "迁移已完成，但服务器重启调度未得到确认；已保留迁移后的面板，请通过服务器控制台确认并在需要时手动重启。"
                result["warnings"].append(reboot_message)
            try:
                await emit("reboot", reboot_message)
            except Exception:
                # A progress write after the final remote command cannot
                # trigger rollback or another connection to a rebooting host.
                result["warnings"].append("迁移结果已确认，但最后的重启状态日志未能保存，请以任务结果中的重启状态为准。")
        return result
    except Exception as exc:
        failure_reason = str(exc) if isinstance(exc, RemoteJobError) else "远程步骤发生异常，已停止执行，请检查服务器和当前任务阶段。"
        if backup_path is not None:
            await emit("rollback", f"任务失败原因：{failure_reason}")
            await emit("rollback", "任务失败，正在尝试恢复原面板和数据库。")
            cleanup_failed = False
            restored = False
            try:
                if conn.is_closed():
                    conn = await _connect(job, ssh_password, options, emit)
            except Exception:
                cleanup_failed = True
            else:
                if acme_started:
                    try:
                        await _remove_acme_job(conn, job)
                    except Exception:
                        cleanup_failed = True
                        await emit("rollback", "本次证书任务清理未完成，继续恢复原面板快照。")
                if bbr_state is not None:
                    try:
                        await _restore_bbr(conn, bbr_state)
                    except Exception:
                        cleanup_failed = True
                        await emit("rollback", "原 BBR 参数恢复未完成，继续恢复原面板快照。")
                try:
                    await rollback_remote(conn, backup_path)
                    restored = True
                    await emit("rollback", "原面板快照已恢复；请通过原地址核对。")
                except Exception:
                    pass
            if not restored:
                await emit("rollback", "自动回滚未完成；请管理员使用服务器备份目录恢复。")
                raise RemoteJobError(f"{failure_reason} 自动回滚未完成，备份目录：{backup_path}") from exc
            if cleanup_failed:
                raise RemoteJobError(f"{failure_reason} 原面板已恢复，但证书或系统参数清理未完成；备份目录：{backup_path}") from exc
        if isinstance(exc, RemoteJobError):
            raise
        raise RemoteJobError("远程任务执行失败，已停止；请查看任务阶段和备份状态。") from exc
    finally:
        await _close_connection(conn, time.monotonic() + 2)

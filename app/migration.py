"""Validate uploaded SQLite snapshots and replace remote databases with rollback.

The SSH helpers support the default Linux/systemd/SQLite installation only. They
never execute SQL or shell text supplied by an uploaded database.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shlex
import sqlite3
import time
from typing import Any

MAX_DATABASE_BYTES = 50 * 1024 * 1024
SUPPORTED_VERSIONS = frozenset({"2.9.4", "3.4.2"})
BACKUP_ROOT = "/var/backups/3xui-web"
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_PORT = re.compile(r"\+?[0-9]{1,5}\Z")
_CERT_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
# Both supported official releases use 2053 and / when these keys are absent:
# v2.9.4/web/service/setting.go and v3.4.2/internal/web/service/setting.go.
DEFAULT_PANEL_PORT = 2053


class MigrationError(ValueError):
    """An invalid snapshot or an unsafe migration request."""


def normalize_panel_path(value: str) -> str:
    """Preserve a safe original base path, matching 3x-ui's slash normalization.

    Root and short or nested paths are valid. Reject ambiguous URL encodings and
    routing components instead of silently rewriting the customer's old path.
    """
    if not isinstance(value, str) or len(value) > 1024:
        raise MigrationError("备份中的面板入口路径无效，不能自动迁移。")
    if any(not (character.isalnum() or character in "/-._~") for character in value):
        raise MigrationError("备份中的面板入口路径含不安全字符，不能自动迁移。")
    if "//" in value or any(part in {".", ".."} for part in value.split("/")):
        raise MigrationError("备份中的面板入口路径含重复斜线或相对路径，不能自动迁移。")
    if not value.startswith("/"):
        value = "/" + value
    if not value.endswith("/"):
        value += "/"
    if len(value) > 1024:
        raise MigrationError("备份中的面板入口路径过长，不能自动迁移。")
    return value


def _port(value: Any, description: str) -> int:
    text = str(value)
    if not _PORT.fullmatch(text) or not 1 <= int(text) <= 65535:
        raise MigrationError(f"备份中的{description}无效，必须为 1–65535。")
    return int(text)


def _version(value: str) -> str:
    normalized = value.removeprefix("v")
    if normalized not in SUPPORTED_VERSIONS:
        raise MigrationError("仅支持 2.9.4 和 3.4.2 版本。")
    return normalized


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_v2_residual_clients(
    db: sqlite3.Connection, tables: set[str], inbound_clients: list[dict[str, Any]],
) -> list[str]:
    """Recognize detached historical tables without rewriting the snapshot.

    A rollback can leave normalized clients whose inbound rows were later
    deleted by 2.x. Only that fully detached shape is accepted here; live or
    unlinked normalized clients still need a source backup in a known layout.
    """
    if not {"clients", "client_inbounds"} & tables:
        return []
    clients = db.execute("SELECT count(*) FROM clients").fetchone()[0] if "clients" in tables else 0
    links = db.execute("SELECT count(*) FROM client_inbounds").fetchone()[0] if "client_inbounds" in tables else 0
    if not clients and not links:
        return ["备份含空的独立客户数据表，可能为历史版本遗留；已按声明的 2.9.4 校验入站客户，原文件及数据表保持不变。"]

    def reject(reason: str) -> None:
        raise MigrationError(
            f"当前选择为 2.9.4 → 2.9.4，但备份的独立客户表 clients 有 {clients} 条记录，"
            f"client_inbounds 有 {links} 条关联。{reason}"
            "2.9.4 只读取入站配置中的客户，不能确认这些独立记录也能恢复，因此已停止以避免客户数据遗漏。"
            "表结构不能证明原面板的精确版本；升级或回退可能留下数据表。"
            "请核对正在运行的原面板版本并重新导出完整备份；不要自行删除数据表或改选版本绕过检查。"
        )

    if not clients or not links:
        reject("独立客户与关联不完整，无法自动确认为历史残留。")
    client_columns = {row[1].casefold() for row in db.execute("PRAGMA table_info(clients)")}
    link_columns = {row[1].casefold() for row in db.execute("PRAGMA table_info(client_inbounds)")}
    if not {"id", "email"}.issubset(client_columns) or not {"client_id", "inbound_id"}.issubset(link_columns):
        reject("独立客户或关联表结构不完整，无法核对历史归属。")
    inbound_columns = {row[1].casefold() for row in db.execute("PRAGMA table_info(inbounds)")}
    if "node_id" in inbound_columns and db.execute(
        "SELECT 1 FROM inbounds WHERE node_id IS NOT NULL "
        "AND (typeof(node_id) != 'integer' OR node_id != 0) LIMIT 1"
    ).fetchone():
        reject("当前入站包含远程节点归属，2.9.4 无法按原节点部署方式恢复。")
    for table in ("clients", "inbounds"):
        if db.execute(f"SELECT 1 FROM {table} WHERE typeof(id) != 'integer' OR id <= 0 LIMIT 1").fetchone():
            reject("客户或入站编号无效，无法核对历史归属。")
        if db.execute(f"SELECT 1 FROM {table} GROUP BY id HAVING count(*) > 1 LIMIT 1").fetchone():
            reject("客户或入站编号重复，无法核对历史归属。")
    if db.execute(
        "SELECT 1 FROM client_inbounds WHERE typeof(client_id) != 'integer' OR client_id <= 0 "
        "OR typeof(inbound_id) != 'integer' OR inbound_id <= 0 LIMIT 1"
    ).fetchone():
        reject("客户关联编号无效，无法核对历史归属。")
    if db.execute(
        "SELECT 1 FROM client_inbounds GROUP BY client_id, inbound_id HAVING count(*) > 1 LIMIT 1"
    ).fetchone():
        reject("客户入站关联重复，无法确认为标准历史残留。")
    if db.execute(
        "SELECT 1 FROM client_inbounds AS link WHERE NOT EXISTS "
        "(SELECT 1 FROM clients WHERE id = link.client_id) LIMIT 1"
    ).fetchone():
        reject("关联表引用了不存在的独立客户，无法确认为历史残留。")
    if db.execute(
        "SELECT 1 FROM clients WHERE NOT EXISTS "
        "(SELECT 1 FROM client_inbounds WHERE client_id = clients.id) LIMIT 1"
    ).fetchone():
        reject("存在没有入站关联的独立客户，无法自动确定其用途。")
    if db.execute(
        "SELECT 1 FROM client_inbounds AS link WHERE EXISTS "
        "(SELECT 1 FROM inbounds WHERE id = link.inbound_id) LIMIT 1"
    ).fetchone():
        reject("独立客户仍关联当前入站，不能作为已删除入站的历史记录处理。")

    # No customer values enter errors or returned statistics. A collision could
    # instead be a stale copy of a current customer with conflicting settings.
    identifiers = {name: set() for name in ("email", "id", "subId", "password", "auth")}
    for client in inbound_clients:
        for name, values in identifiers.items():
            value = client.get(name)
            if value is not None and not isinstance(value, str):
                reject("当前入站客户标识类型异常，无法核对历史记录。")
            if isinstance(value, str) and value:
                values.add(value.casefold())
    mapped = {"email": "email", "uuid": "id", "sub_id": "subId", "password": "password", "auth": "auth"}
    selected = [(column, field) for column, field in mapped.items() if column in client_columns]
    for row in db.execute("SELECT " + ", ".join(column for column, _ in selected) + " FROM clients"):
        for value, (_, field) in zip(row, selected):
            if value is not None and not isinstance(value, str):
                reject("独立客户标识类型异常，无法确认为历史残留。")
            if field == "email" and (not value or not value.strip()):
                reject("独立客户缺少客户标识，无法确认为标准历史残留。")
            if value and value.casefold() in identifiers[field]:
                reject("历史独立客户与当前入站客户的标识重叠，无法自动确认两套数据是否一致。")
    return [
        f"已自动核对：{clients} 条独立客户记录的 {links} 条关联均仅指向已删除入站，作为历史残留原样保留；"
        "2.9.4 仅按当前入站 JSON 中的客户恢复和验收，这些历史记录不计入当前客户数。"
    ]


def validate_database(path: Path, source_version: str, target_version: str) -> dict[str, Any]:
    """Inspect an upload without modifying it or creating SQLite sidecar files.

    The source version is customer-declared: SQLite does not reliably record the
    release which produced a snapshot. Structural checks catch obvious mismatches
    but cannot authenticate that declaration.
    """
    source_version, target_version = _version(source_version), _version(target_version)
    if source_version != target_version:
        raise MigrationError("首版仅支持同版本迁移，请选择与原面板相同的目标版本。")
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise MigrationError("请上传一个完整的 SQLite 数据库文件。")
    size = path.stat().st_size
    if size > MAX_DATABASE_BYTES:
        raise MigrationError("数据库不能超过 50 MiB。")
    with path.open("rb") as source:
        if source.read(16) != b"SQLite format 3\x00":
            raise MigrationError("文件不是 SQLite 数据库，不能仅修改扩展名后上传。")
    warnings: list[str] = []
    dependencies: set[str] = set()
    two_factor_enabled = False
    deadline = time.monotonic() + 15
    db: sqlite3.Connection | None = None
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        checks = db.execute("PRAGMA integrity_check").fetchmany(2)
        if checks != [("ok",)]:
            raise MigrationError("数据库完整性检查失败，请从原面板重新导出。")
        schema = db.execute("SELECT type, sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
        if any(kind in {"trigger", "view"} or "CREATE VIRTUAL TABLE" in sql.upper() for kind, sql in schema):
            raise MigrationError("数据库含非标准触发器、视图或虚拟表，不能自动迁移。")
        # SQLite identifiers are case insensitive, including historical tables.
        tables = {row[0].casefold() for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"users", "settings", "inbounds"}.issubset(tables):
            raise MigrationError("缺少 3x-ui 必需的数据表：users、settings、inbounds。")
        columns = {
            table: {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            for table in ("users", "settings", "inbounds")
        }
        if not {"username", "password"}.issubset(columns["users"]):
            raise MigrationError("users 数据表结构无效。")
        if not {"key", "value"}.issubset(columns["settings"]):
            raise MigrationError("settings 数据表结构无效。")
        if not {"id", "settings"}.issubset(columns["inbounds"]):
            raise MigrationError("inbounds 数据表结构无效。")
        if source_version == "3.4.2" and "clients" not in tables:
            raise MigrationError("当前选择为 3.4.2 → 3.4.2，但备份缺少本工具校验所需的独立 clients 数据表。请核对正在运行的原面板版本并重新导出，不要改选版本绕过检查。")
        inbound_count = db.execute("SELECT count(*) FROM inbounds").fetchone()[0]
        user_count = db.execute("SELECT count(*) FROM users").fetchone()[0]
        if not user_count:
            raise MigrationError("数据库没有面板账号，不能作为完整面板备份迁移。")
        inbound_ports = sorted({
            _port(row[0], "入站端口") for row in db.execute("SELECT port FROM inbounds")
        }) if "port" in columns["inbounds"] else []

        def inspect(value: Any, key: str = "") -> None:
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    inspect(child_value, str(child_key))
            elif isinstance(value, list):
                for child in value:
                    inspect(child, key)
            elif isinstance(value, str) and len(dependencies) < 100:
                if key.lower() in {"certificatefile", "keyfile", "certfile", "privatekeyfile", "path", "geosite", "geoip"}:
                    if value.startswith(("/", "./", "../", "ext:")):
                        dependencies.add(value[:500])

        selected = ["settings"]
        selected += [name for name in ("stream_settings", "sniffing", "allocate") if name in columns["inbounds"]]
        client_count = 0
        inbound_clients: list[dict[str, Any]] = []
        for row in db.execute("SELECT " + ", ".join(selected) + " FROM inbounds"):
            for index, raw in enumerate(row):
                if not raw:
                    continue
                if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024:
                    raise MigrationError("入站配置异常或过大，请检查原面板备份。")
                try:
                    payload = json.loads(raw)
                except (ValueError, RecursionError) as exc:
                    raise MigrationError("入站配置不是有效 JSON，请检查原面板备份。") from exc
                if index == 0 and source_version == "2.9.4":
                    clients = payload.get("clients", []) if isinstance(payload, dict) else []
                    if not isinstance(payload, dict) or not isinstance(clients, list) or any(not isinstance(client, dict) for client in clients):
                        raise MigrationError("入站客户配置不是有效的 JSON 对象列表，请重新导出完整备份。")
                    client_count += len(clients)
                    inbound_clients.extend(clients)
                try:
                    inspect(payload)
                except RecursionError as exc:
                    raise MigrationError("入站配置嵌套过深。") from exc
        if source_version == "2.9.4":
            warnings.extend(_validate_v2_residual_clients(db, tables, inbound_clients))
            if "api_tokens" in tables and db.execute("SELECT 1 FROM api_tokens LIMIT 1").fetchone():
                warnings.append("备份中的 3.x API 令牌数据表将原样保留，但 2.9.4 不读取该表；依赖这些令牌的接口需单独核对。")
        if source_version == "3.4.2":
            client_count = db.execute("SELECT count(*) FROM clients").fetchone()[0]
        panel_values: dict[str, Any] = {}
        for key, value in db.execute("SELECT key, value FROM settings"):
            if key in {"webPort", "webBasePath"}:
                if key in panel_values:
                    raise MigrationError("备份中的面板端口或入口路径设置重复，不能确定原面板配置。")
                panel_values[key] = value
            if key in {"webCertFile", "webKeyFile", "subCertFile", "subKeyFile"} and value:
                dependencies.add(str(value)[:500])
            if key in {"subDomain", "subURI", "subJsonURI"} and value:
                warnings.append("备份含旧订阅域名或订阅地址，迁移后需核对。")
            if key == "twoFactorEnable" and str(value).lower() == "true":
                two_factor_enabled = True
                warnings.append("原面板启用了二次验证；迁移后仍需原验证器验证码。")
        if "webPort" not in panel_values or (source_version == "3.4.2" and panel_values["webPort"] == ""):
            panel_port = DEFAULT_PANEL_PORT
            warnings.append("备份未设置面板端口，将沿用该版本官方默认端口 2053。")
        else:
            panel_port = _port(panel_values["webPort"], "面板端口 webPort")
        if "webBasePath" not in panel_values:
            warnings.append("备份未设置面板入口路径，将沿用该版本官方默认路径 /。")
        panel_path = normalize_panel_path(panel_values.get("webBasePath", "/"))
        if dependencies:
            warnings.append("数据库引用外部证书或文件；上传数据库不包含这些文件，入站与订阅需单独核对。")
        if user_count > 1:
            warnings.append("备份含多个面板账号；迁移将全部保留原账号和密码。")
        warnings.append("请使用原面板导出的完整备份；单独复制运行中的 .db 可能缺少 WAL 中的数据。")
        return {
            "source_version": source_version,
            "target_version": target_version,
            "size_bytes": size,
            "sha256": _sha256(path),
            "inbounds": inbound_count,
            "clients": client_count,
            "client_count_kind": "入站客户条目" if source_version == "2.9.4" else "客户记录",
            "users": user_count,
            "two_factor_enabled": two_factor_enabled,
            "panel_settings": {"port": panel_port, "path": panel_path},
            "inbound_ports": inbound_ports,
            "external_dependencies": sorted(dependencies),
            "warnings": list(dict.fromkeys(warnings)),
        }
    except (sqlite3.Error, OSError) as exc:
        raise MigrationError("数据库无法安全读取或检查超时，请重新导出后上传。") from exc
    finally:
        if db is not None:
            db.close()


def _job_id(value: str) -> str:
    if not _JOB_ID.fullmatch(value):
        raise MigrationError("无效的任务编号。")
    return value


def _backup_path(value: str) -> str:
    prefix = BACKUP_ROOT + "/"
    if not value.startswith(prefix) or not _JOB_ID.fullmatch(value[len(prefix):]):
        raise MigrationError("无效的备份目录。")
    return value


def _certificate_domain(value: str) -> str:
    if not isinstance(value, str) or not _CERT_DOMAIN.fullmatch(value):
        raise MigrationError("无效的证书域名，不能确定安全的证书目录。")
    return value


_REMOTE_COMMON = r'''
import hashlib, json, os, re, shutil, sqlite3, stat, subprocess, sys
from pathlib import Path
ROOT = Path('/var/backups/3xui-web')
PATHS = ('/usr/local/x-ui', '/usr/bin/x-ui', '/etc/x-ui',
         '/etc/systemd/system/x-ui.service', '/etc/systemd/system/x-ui.service.d',
         '/usr/lib/systemd/system/x-ui.service', '/lib/systemd/system/x-ui.service',
         '/etc/default/x-ui', '/etc/systemd/system/multi-user.target.wants/x-ui.service')
def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            result.update(chunk)
    return result.hexdigest()
def systemctl(*args, check=True):
    return subprocess.run(['systemctl', *args], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
def exists(path):
    return os.path.lexists(path)
def safe_backup(path):
    if path.parent != ROOT or not path.name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in path.name):
        raise RuntimeError('Invalid backup path')
    if ROOT.is_symlink() or path.is_symlink():
        raise RuntimeError('Backup path cannot be a symbolic link')
def metadata(path):
    result = {}
    items = [path]
    if path.is_dir() and not path.is_symlink():
        for root, dirs, files in os.walk(path, followlinks=False):
            items.extend(Path(root) / name for name in dirs + files)
    for item in items:
        info = item.lstat()
        result[str(item.relative_to(path))] = [stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid]
    return result
def readonly(path):
    if path.is_symlink():
        return
    if path.is_dir():
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for name in files:
                item = Path(root) / name
                if not item.is_symlink(): os.chmod(item, 0o400)
            for name in dirs:
                item = Path(root) / name
                if not item.is_symlink(): os.chmod(item, 0o500)
        os.chmod(path, 0o500)
    else:
        os.chmod(path, 0o400)
def copy_item(source, destination):
    if source.is_dir() and not source.is_symlink():
        shutil.copytree(source, destination, symlinks=True)
    else:
        shutil.copy2(source, destination, follow_symlinks=False)
def certificate_name(domain):
    if not isinstance(domain, str) or not re.fullmatch(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z', domain):
        raise RuntimeError('Invalid certificate domain')
    return '/root/cert/' + domain

def safe_certificate_tree(path):
    if path.is_symlink() or (exists(path) and not path.is_dir()):
        raise RuntimeError('Certificate directory must be a real directory')
    if path.is_dir():
        for root, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                mode = (Path(root) / name).lstat().st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise RuntimeError('Certificate tree contains a symbolic link or special file')

def safe_certificate_target(name):
    root = Path('/root/cert')
    for parent in (root.parent, root):
        if parent.is_symlink() or (exists(parent) and not parent.is_dir()):
            raise RuntimeError('Certificate parent must be a real directory')
    target = Path(name)
    safe_certificate_tree(target)
    return target

def manifest_paths(manifest):
    names = list(PATHS)
    if 'cert_domain' in manifest:
        names.append(certificate_name(manifest['cert_domain']))
    return names

def load_manifest(path):
    safe_backup(path)
    manifest = json.loads((path / 'manifest.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('complete') is not True:
        raise RuntimeError('Backup is not complete')
    if manifest.get('job_id') != path.name:
        raise RuntimeError('Backup job identifier does not match its directory')
    if set(manifest.get('entries', {})) != set(manifest_paths(manifest)):
        raise RuntimeError('Unexpected backup entries')
    return manifest
'''

_BACKUP_SCRIPT = _REMOTE_COMMON + r'''
job_id = sys.argv[1]
cert_domain = sys.argv[2] if len(sys.argv) > 2 else None
cert_name = certificate_name(cert_domain) if cert_domain is not None else None
if cert_name is not None: safe_certificate_target(cert_name)
backup = ROOT / job_id
safe_backup(backup)
if os.geteuid() != 0:
    raise RuntimeError('Root SSH account is required')
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(ROOT, 0o700)
backup.mkdir(mode=0o700)
snapshot = backup / 'snapshot'
snapshot.mkdir(mode=0o700)
was_active = systemctl('is-active', '--quiet', 'x-ui.service', check=False).returncode == 0
enabled = systemctl('is-enabled', 'x-ui.service', check=False).stdout.strip()
manifest = {'schema': 1, 'complete': False, 'job_id': job_id,
            'was_active': was_active, 'enabled': enabled, 'entries': {}}
if cert_domain is not None: manifest['cert_domain'] = cert_domain
try:
    if systemctl('show', '-p', 'LoadState', '--value', 'x-ui.service', check=False).stdout.strip() not in ('', 'not-found'):
        systemctl('stop', 'x-ui.service')
    for name in manifest_paths(manifest):
        source = safe_certificate_target(name) if name == cert_name else Path(name)
        entry = {'exists': exists(source)}
        if entry['exists']:
            if name in ('/usr/local/x-ui', '/etc/x-ui') and source.is_symlink():
                raise RuntimeError('Non-standard symbolic-link installation is not supported')
            entry['metadata'] = metadata(source)
            target = snapshot / name.lstrip('/')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            copy_item(source, target)
        manifest['entries'][name] = entry
    original_db = Path('/etc/x-ui/x-ui.db')
    if exists(original_db):
        if original_db.is_symlink() or not original_db.is_file():
            raise RuntimeError('Non-standard database path is not supported')
        target = snapshot / 'etc/x-ui/x-ui.db'
        target.unlink()
        source = sqlite3.connect(original_db.as_uri() + '?mode=ro', uri=True)
        destination = sqlite3.connect(str(target))
        try:
            source.backup(destination)
            if destination.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise RuntimeError('Original database integrity check failed')
        finally:
            destination.close()
            source.close()
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(target) + suffix)
            if exists(sidecar): sidecar.unlink()
            manifest['entries']['/etc/x-ui']['metadata'].pop('x-ui.db' + suffix, None)
        manifest['database_sha256'] = digest(target)
    manifest['complete'] = True
    (backup / 'manifest.json').write_text(json.dumps(manifest))
    readonly(snapshot)
    os.chmod(backup / 'manifest.json', 0o400)
    os.chmod(backup, 0o500)
    print(json.dumps({'backup_path': str(backup)}))
except Exception:
    if was_active:
        systemctl('start', 'x-ui.service', check=False)
    raise
'''

_PREPARE_IMPORT_SCRIPT = _REMOTE_COMMON + r'''
backup = Path(sys.argv[1])
manifest = load_manifest(backup)
systemctl('stop', 'x-ui.service')
directory = Path('/etc/x-ui')
if directory.is_symlink(): raise RuntimeError('Database directory cannot be a symbolic link')
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
temporary = directory / ('.x-ui-upload-' + manifest['job_id'] + '.db')
fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
print(json.dumps({'temporary_path': str(temporary)}))
'''

_COMMIT_IMPORT_SCRIPT = _REMOTE_COMMON + r'''
backup, expected_hash = Path(sys.argv[1]), sys.argv[2]
manifest = load_manifest(backup)
temporary = Path('/etc/x-ui') / ('.x-ui-upload-' + manifest['job_id'] + '.db')
if temporary.is_symlink() or not temporary.is_file():
    raise RuntimeError('Uploaded database is missing or unsafe')
if temporary.stat().st_size > 52428800 or digest(temporary) != expected_hash:
    raise RuntimeError('Uploaded database checksum mismatch')
db = sqlite3.connect(temporary.as_uri() + '?mode=ro&immutable=1', uri=True)
try:
    db.execute('PRAGMA trusted_schema=OFF')
    if db.execute('PRAGMA integrity_check').fetchone() != ('ok',):
        raise RuntimeError('Uploaded database integrity check failed')
    has_two_factor = db.execute("SELECT 1 FROM settings WHERE key='twoFactorEnable' AND lower(value)='true' LIMIT 1").fetchone() is not None
    inbounds = db.execute('SELECT count(*) FROM inbounds').fetchone()[0]
finally:
    db.close()
systemctl('stop', 'x-ui.service')
target = Path('/etc/x-ui/x-ui.db')
for suffix in ('-wal', '-shm', '-journal'):
    sidecar = Path(str(target) + suffix)
    if exists(sidecar): sidecar.unlink()
os.chmod(temporary, 0o600)
os.chown(temporary, 0, 0)
with temporary.open('rb') as stream: os.fsync(stream.fileno())
os.replace(temporary, target)
fd = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
print(json.dumps({'sha256': expected_hash, 'database_path': str(target), 'backup_path': str(backup),
                  'has_two_factor': has_two_factor, 'inbounds': inbounds, 'warnings': []}))
'''

_ROLLBACK_SCRIPT = _REMOTE_COMMON + r'''
backup = Path(sys.argv[1])
manifest = load_manifest(backup)
cert_name = certificate_name(manifest['cert_domain']) if 'cert_domain' in manifest else None
if cert_name is not None:
    safe_certificate_target(cert_name)
    if manifest['entries'][cert_name]['exists']:
        saved_cert = backup / 'snapshot' / cert_name.lstrip('/')
        for parent in (saved_cert.parent.parent, saved_cert.parent):
            if parent.is_symlink() or not parent.is_dir():
                raise RuntimeError('Unsafe certificate snapshot parent')
        if not saved_cert.is_dir(): raise RuntimeError('Missing certificate snapshot')
        safe_certificate_tree(saved_cert)
if manifest.get('database_sha256'):
    saved_db = backup / 'snapshot/etc/x-ui/x-ui.db'
    if digest(saved_db) != manifest['database_sha256']:
        raise RuntimeError('Backup database checksum mismatch')
systemctl('stop', 'x-ui.service', check=False)
restored = set()
for name in manifest_paths(manifest):
    target = safe_certificate_target(name) if name == cert_name else Path(name)
    # /lib may alias /usr/lib; preserve each physical unit once.
    identity = str(target.parent.resolve() / target.name)
    if identity in restored: continue
    restored.add(identity)
    entry = manifest['entries'][name]
    source = backup / 'snapshot' / name.lstrip('/')
    temporary = target.with_name('.' + target.name + '.restore-' + manifest['job_id'])
    displaced = target.with_name('.' + target.name + '.failed-' + manifest['job_id'])
    if exists(temporary) or exists(displaced):
        raise RuntimeError('Rollback staging path already exists; manual review required')
    if entry['exists']:
        target.parent.mkdir(parents=True, exist_ok=True)
        copy_item(source, temporary)
        for relative, details in entry['metadata'].items():
            item = temporary if relative == '.' else temporary / relative
            if not exists(item): continue
            mode, uid, gid = details
            os.chown(item, uid, gid, follow_symlinks=False)
            if not item.is_symlink(): os.chmod(item, mode)
        if exists(target): os.replace(target, displaced)
        os.replace(temporary, target)
    elif exists(target):
        os.replace(target, displaced)
    if name == cert_name and exists(displaced):
        # Only this validated domain directory is removed; siblings are untouched.
        safe_certificate_tree(displaced)
        shutil.rmtree(displaced)
systemctl('daemon-reload')
if manifest['enabled'] in ('enabled', 'enabled-runtime'):
    args = ['enable']
    if manifest['enabled'] == 'enabled-runtime': args.append('--runtime')
    systemctl(*args, 'x-ui.service')
else:
    systemctl('disable', 'x-ui.service', check=False)
if manifest['was_active']:
    systemctl('start', 'x-ui.service')
    systemctl('is-active', '--quiet', 'x-ui.service')
print(json.dumps({'restored': True, 'was_active': manifest['was_active']}))
'''


async def _remote_json(conn: Any, script: str, *args: str) -> dict[str, Any]:
    command = "python3 - " + " ".join(shlex.quote(value) for value in args)
    result = await conn.run(command, input=script, check=True, timeout=180)
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise MigrationError("服务器返回了无效的备份或迁移结果。") from exc


async def backup_remote(conn: Any, job_id: str, cert_domain: str | None = None) -> str:
    """Stop the original service and preserve its files before installation."""
    arguments = [_job_id(job_id)]
    if cert_domain is not None:
        arguments.append(_certificate_domain(cert_domain))
    result = await _remote_json(conn, _BACKUP_SCRIPT, *arguments)
    return _backup_path(result["backup_path"])


async def import_remote_database(conn: Any, local_path: Path, backup_path: str, job_id: str) -> dict[str, Any]:
    """Replace the stopped SQLite database; leave the service stopped for setup."""
    job_id, backup_path = _job_id(job_id), _backup_path(backup_path)
    if backup_path != f"{BACKUP_ROOT}/{job_id}":
        raise MigrationError("备份目录与当前任务不匹配。")
    local_path = Path(local_path)
    if local_path.is_symlink() or not local_path.is_file() or local_path.stat().st_size > MAX_DATABASE_BYTES:
        raise MigrationError("数据库文件不存在或超过大小限制。")
    expected_hash = _sha256(local_path)
    prepared = await _remote_json(conn, _PREPARE_IMPORT_SCRIPT, backup_path)
    expected_path = f"/etc/x-ui/.x-ui-upload-{job_id}.db"
    if prepared.get("temporary_path") != expected_path:
        raise MigrationError("服务器返回了无效的上传路径。")
    async with conn.start_sftp_client() as sftp:
        await sftp.put(str(local_path), expected_path)
    return await _remote_json(conn, _COMMIT_IMPORT_SCRIPT, backup_path, expected_hash)


async def rollback_remote(conn: Any, backup_path: str) -> None:
    """Restore the original binary, configuration, snapshot and service state."""
    await _remote_json(conn, _ROLLBACK_SCRIPT, _backup_path(backup_path))

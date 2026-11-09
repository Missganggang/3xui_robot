import asyncio
import base64
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import shlex
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock
import urllib.request

import asyncssh
import httpx
import pytest

from app import remote


def job(**changes):
    base = dict(id="task_123", kind="install", server_ip="8.8.8.8", ssh_port=22,
                ssh_username="root", domain="panel.example.com", version="v2.9.4",
                panel_port=443, panel_path="/abcdefghijkl/", overwrite_existing=False,
                reset_two_factor=False, validation=None)
    return base | changes


def options(tmp_path):
    return remote.RemoteOptions(known_hosts_path=tmp_path / "ssh" / "known_hosts")


@pytest.mark.parametrize("changes", [
    {"server_ip": "127.0.0.1"}, {"server_ip": "169.254.169.254"},
    {"server_ip": "10.0.0.1"}, {"server_ip": "::1"}, {"panel_port": 80},
    {"panel_port": 22}, {"domain": "x;reboot.example.com"},
    {"panel_path": "/hello/$(reboot)/"}, {"version": "main"}, {"id": "../../root"},
    {"ssh_username": "nobody"}, {"kind": "migrate", "source_version": "3.4.2"},
])
def test_rejects_unsafe_remote_targets_and_shell_inputs(tmp_path, changes):
    with pytest.raises(remote.RemoteJobError):
        remote._validate_job(job(**changes), options(tmp_path))


def test_private_targets_require_explicit_server_setting(tmp_path):
    opts = remote.RemoteOptions(known_hosts_path=tmp_path / "hosts", allow_private_targets=True)
    assert remote._validate_job(job(server_ip="10.0.0.9"), opts)["server_ip"] == "10.0.0.9"


def test_legacy_pin_check_remains_compatible_with_manual_maintenance(tmp_path):
    path = options(tmp_path).known_hosts_path
    first = asyncssh.generate_private_key("ssh-ed25519")
    changed = asyncssh.generate_private_key("ssh-ed25519")
    assert remote._record_host_key(path, "8.8.8.8", 2222, first)
    assert remote._record_host_key(path, "8.8.8.8", 2222, first)
    saved = path.read_bytes()
    assert not remote._record_host_key(path, "8.8.8.8", 2222, changed)
    assert path.read_bytes() == saved
    assert remote._record_host_key(path, "8.8.8.8", 22, changed)


@pytest.mark.parametrize('kind', ['install', 'migrate'])
def test_ssh_handshake_automatically_updates_rotated_key_and_logs_both_fingerprints(tmp_path, kind):
    from app.host_keys import read_host_keys

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True
        def password_auth_supported(self):
            return True
        def validate_password(self, username, password):
            return username == "root" and password == "test-password"

    async def scenario():
        first_key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[first_key])
        port = server.get_port()
        local_job = job(kind=kind, server_ip="127.0.0.1", ssh_port=port)
        emit = AsyncMock()
        try:
            connection = await remote._connect(local_job, "test-password", options(tmp_path), emit)
            connection.close()
            await connection.wait_closed()
            assert options(tmp_path).known_hosts_path.exists()
        finally:
            server.close()
            await server.wait_closed()
        assert emit.await_count == 0
        rotated_key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(Server, "127.0.0.1", port,
            server_host_keys=[rotated_key], reuse_address=True)
        try:
            connection = await remote._connect(local_job, "test-password", options(tmp_path), emit)
            connection.close()
            await connection.wait_closed()
            assert read_host_keys(options(tmp_path).known_hosts_path, '127.0.0.1', port) == [
                rotated_key.export_public_key('openssh').decode().strip()]
            emit.assert_awaited_once()
            stage, message = emit.await_args.args
            assert stage == 'connect' and '系统已自动确认并更新' in message
            assert first_key.get_fingerprint('sha256') in message
            assert rotated_key.get_fingerprint('sha256') in message
            assert 'test-password' not in message
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_rotated_key_is_logged_even_when_ssh_password_is_wrong(tmp_path):
    from app.host_keys import read_host_keys

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username): return True
        def password_auth_supported(self): return True
        def validate_password(self, username, password): return False

    async def scenario():
        previous, current = [asyncssh.generate_private_key('ssh-ed25519') for _ in range(2)]
        server = await asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[current])
        port = server.get_port()
        remote._record_host_key(options(tmp_path).known_hosts_path, '127.0.0.1', port, previous)
        emit = AsyncMock()
        try:
            with pytest.raises(remote.RemoteJobError, match='SSH 登录失败'):
                await remote._connect(job(server_ip='127.0.0.1', ssh_port=port), 'wrong-private-password', options(tmp_path), emit)
            assert read_host_keys(options(tmp_path).known_hosts_path, '127.0.0.1', port) == [current.export_public_key('openssh').decode().strip()]
            emit.assert_awaited_once()
            assert previous.get_fingerprint('sha256') in emit.await_args.args[1]
            assert current.get_fingerprint('sha256') in emit.await_args.args[1]
            assert 'wrong-private-password' not in str(emit.await_args)
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_rotated_key_audit_failure_closes_authenticated_connection(tmp_path, monkeypatch):
    old, new = [asyncssh.generate_private_key('ssh-ed25519') for _ in range(2)]
    path = options(tmp_path).known_hosts_path
    remote._record_host_key(path, '8.8.8.8', 22, old)
    connection = SimpleNamespace(close=AsyncMock(), wait_closed=AsyncMock())
    connection.close = lambda: setattr(connection, 'closed', True)
    async def connect(*args, **kwargs):
        client = kwargs['client_factory']()
        assert client.validate_host_public_key('8.8.8.8', '8.8.8.8', 22, new)
        return connection
    monkeypatch.setattr(remote.asyncssh, 'connect', connect)
    with pytest.raises(remote.RemoteJobError, match='无法保存任务日志'):
        asyncio.run(remote._connect(job(), 'private-password', options(tmp_path), AsyncMock(side_effect=OSError('local audit unavailable'))))
    assert connection.closed
    connection.wait_closed.assert_awaited_once()


def test_installer_is_fail_closed_and_does_not_start_unconfigured_panel(monkeypatch):
    source = b"install_x-ui() {\n    config_after_install\n            systemctl start x-ui\n}\nhttps://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh\n"
    monkeypatch.setitem(remote.INSTALLER_SHA256, "v2.9.4", hashlib.sha256(source).hexdigest())
    output, digest = remote._prepare_installer(source, "v2.9.4")
    assert b"    config_after_install\n" not in output
    assert b"systemctl start x-ui" not in output
    assert b'"${xui_folder}/x-ui" migrate' in output
    assert b"/v2.9.4/x-ui.sh" in output
    assert digest == hashlib.sha256(source).hexdigest()
    with pytest.raises(remote.RemoteJobError, match="不一致"):
        remote._prepare_installer(source + b"# changed", "v2.9.4")
    changed_structure = source.replace(b"    config_after_install\n", b"something_else\n")
    monkeypatch.setitem(remote.INSTALLER_SHA256, "v2.9.4", hashlib.sha256(changed_structure).hexdigest())
    with pytest.raises(remote.RemoteJobError, match="结构"):
        remote._prepare_installer(changed_structure, "v2.9.4")


def test_dns_rejects_extra_and_private_addresses(tmp_path, monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        public = AsyncMock(return_value=[
            {"source": source, "addresses": ["8.8.8.8", "1.1.1.1"], "error": None}
            for source in ("AliDNS", "DNSPod")])
        monkeypatch.setattr(remote, "resolve_public_dns", public)
        monkeypatch.setattr(loop, "getaddrinfo", AsyncMock(return_value=[
            (2, 1, 6, "", ("8.8.8.8", 0)), (2, 1, 6, "", ("1.1.1.1", 0))]))
        with pytest.raises(remote.RemoteJobError, match="其他 IP"):
            await remote._check_dns(job(), options(tmp_path))
        loop.getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]
        public.return_value = [
            {"source": source, "addresses": ["127.0.0.1"], "error": None}
            for source in ("AliDNS", "DNSPod")]
        with pytest.raises(remote.RemoteJobError, match="公网 IP"):
            await remote._check_dns(job(), options(tmp_path))
    asyncio.run(scenario())


def test_https_probes_pin_ip_and_verify_domain_sni(monkeypatch):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"success": True}) if request.method == "POST" else httpx.Response(200, text="panel")
    original = httpx.AsyncClient
    monkeypatch.setattr(remote.httpx, "AsyncClient", lambda **kwargs: original(
        **kwargs, transport=httpx.MockTransport(handler)))
    asyncio.run(remote._verify_https_login(job()))
    assert [request.method for request in seen] == ["GET", "POST"]
    for request in seen:
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == "panel.example.com"
        assert request.extensions["sni_hostname"] == "panel.example.com"
    assert seen[1].url.path == "/abcdefghijkl/login"


def test_failed_panel_login_is_never_reported_as_success(monkeypatch):
    original = httpx.AsyncClient
    monkeypatch.setattr(remote.httpx, "AsyncClient", lambda **kwargs: original(
        **kwargs, transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"success": False}))
    ))
    with pytest.raises(remote.RemoteJobError, match="登录验收失败"):
        asyncio.run(remote._verify_https_login(job()))


def test_v342_login_initializes_csrf_session_and_sends_cookie(monkeypatch):
    seen = []
    token = "a" * 43
    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/csrf-token"):
            return httpx.Response(200, json={"success": True, "obj": token},
                                  headers={"Set-Cookie": "3x-ui=session-value; Path=/abcdefghijkl/; Secure; HttpOnly"})
        if request.method == "POST":
            assert request.headers["X-CSRF-Token"] == token
            assert "3x-ui=session-value" in request.headers["Cookie"]
            return httpx.Response(200, json={"success": True})
        return httpx.Response(200, text="panel")
    original = httpx.AsyncClient
    monkeypatch.setattr(remote.httpx, "AsyncClient", lambda **kwargs: original(
        **kwargs, transport=httpx.MockTransport(handler)))
    asyncio.run(remote._verify_https_login(job(version="v3.4.2")))
    assert [request.url.path for request in seen] == ["/abcdefghijkl/", "/abcdefghijkl/csrf-token", "/abcdefghijkl/login"]
    assert all(request.extensions["sni_hostname"] == "panel.example.com" for request in seen)


def test_v342_refuses_login_without_valid_csrf_token(monkeypatch):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"success": True, "obj": ""})
    original = httpx.AsyncClient
    monkeypatch.setattr(remote.httpx, "AsyncClient", lambda **kwargs: original(
        **kwargs, transport=httpx.MockTransport(handler)))
    with pytest.raises(remote.RemoteJobError, match="会话初始化失败"):
        asyncio.run(remote._verify_https_login(job(version="v3.4.2")))
    assert all(request.method == "GET" for request in seen)


def test_generated_bbr_script_is_valid_python_and_keeps_restore_state(monkeypatch):
    commands = []
    async def run(conn, command, **kwargs):
        commands.append(command)
        if command.startswith("python3 -c "):
            compile(shlex.split(command)[2], "remote-bbr", "exec")
            return json.dumps({"qdisc": "fq_codel", "control": "cubic", "file": None})
        return ""
    monkeypatch.setattr(remote, "_run", run)
    monkeypatch.setattr(remote, "_verify_bbr", AsyncMock())
    state = asyncio.run(remote._enable_bbr(object()))
    assert state["control"] == "cubic"
    assert commands[-1] == "sysctl -p " + remote.BBR_CONFIG


@pytest.mark.parametrize("kind,version,domain", [
    ("install", "v2.9.4", "panel.example.com"),
    ("migrate", "v2.9.4", "panel.example.com"),
    ("install", "v3.4.2", "panel.example.com"),
    ("migrate", "v3.4.2", "panel.example.com"),
])
def test_certificate_install_binding_expiry_and_renewal_use_domain_directory(tmp_path, monkeypatch, kind, version, domain):
    commands = []
    sandbox_root = tmp_path / "root"
    async def run(conn, command, *args, **kwargs):
        commands.append(command)
        if len(commands) == 1:
            # Run the generated path checks against a local temporary root.
            exec(shlex.split(command)[2].replace('/root', sandbox_root.as_posix()), {})
        elif command.startswith('openssl x509 '):
            return 'notAfter=Jan 01 00:00:00 2027 GMT\n'
        return ''
    monkeypatch.setattr(remote, '_run', run)
    result = asyncio.run(remote._issue_certificate(object(), job(kind=kind, version=version, domain=domain), options(tmp_path)))
    cert = f'/root/cert/{domain}/fullchain.pem'
    key = f'/root/cert/{domain}/privkey.pem'
    assert (sandbox_root / 'cert' / domain).is_dir()
    issue = commands[1]
    install = shlex.split(next(line for line in issue.splitlines() if '--install-cert' in line))
    binding = shlex.split(next(line for line in issue.splitlines() if ' cert -webCert ' in line))
    assert install[install.index('--key-file') + 1] == key
    assert install[install.index('--fullchain-file') + 1] == cert
    assert install[install.index('--reloadcmd') + 1] == 'systemctl try-restart x-ui'
    assert binding[binding.index('-webCert') + 1] == cert
    assert binding[binding.index('-webCertKey') + 1] == key
    home = install[install.index('--home') + 1]
    cron_code = shlex.split(commands[2])[2]
    assert f'{home}/acme.sh --cron --home {home}' in cron_code
    compile(cron_code, 'certificate-renewal', 'exec')
    assert shlex.split(commands[3])[3] == cert
    assert result['certificate_file'] == cert and result['private_key_file'] == key
    assert result['auto_renew'] is True
    assert result['expires_at'] == 'Jan 01 00:00:00 2027 GMT'
    assert '/etc/x-ui/cert/' not in '\n'.join(commands)


@pytest.mark.parametrize('unsafe', ['parent_file', 'domain_file', 'key_directory'])
def test_certificate_preparation_stops_before_issuance_for_unsafe_paths(tmp_path, monkeypatch, unsafe):
    sandbox_root = tmp_path / 'root'
    sandbox_root.mkdir()
    if unsafe == 'parent_file':
        (sandbox_root / 'cert').write_text('preserve-me')
    elif unsafe == 'domain_file':
        (sandbox_root / 'cert').mkdir()
        (sandbox_root / 'cert' / 'panel.example.com').write_text('preserve-me')
    else:
        (sandbox_root / 'cert' / 'panel.example.com' / 'privkey.pem').mkdir(parents=True)
    calls = []
    async def run(conn, command, *args, **kwargs):
        calls.append(command)
        exec(shlex.split(command)[2].replace('/root', sandbox_root.as_posix()), {})
        return ''
    monkeypatch.setattr(remote, '_run', run)
    with pytest.raises(RuntimeError, match='Unsafe certificate'):
        asyncio.run(remote._issue_certificate(object(), job(domain='panel.example.com'), options(tmp_path)))
    assert len(calls) == 1


def _wire_install(monkeypatch, existing=False):
    connection = SimpleNamespace(close=lambda: None, wait_closed=AsyncMock(), is_closed=lambda: False)
    monkeypatch.setattr(remote, "_connect", AsyncMock(return_value=connection))
    monkeypatch.setattr(remote, "_check_dns", AsyncMock())
    monkeypatch.setattr(remote, "_run", AsyncMock(return_value=json.dumps({"existing": existing})))
    for name in ("_probe_port", "_install", "_configure", "_configure_restored", "_verify_temporary_installation",
                 "_verify_preserved_migration_state", "_wait_for_panel", "_verify_bbr", "_finalize_acme"):
        monkeypatch.setattr(remote, name, AsyncMock())
    monkeypatch.setattr(remote, "backup_remote", AsyncMock(return_value="/var/backups/3xui-web/task_123"))
    monkeypatch.setattr(remote, "rollback_remote", AsyncMock())
    monkeypatch.setattr(remote, "_remove_acme_job", AsyncMock())
    monkeypatch.setattr(remote, "_restore_bbr", AsyncMock())
    monkeypatch.setattr(remote, "_enable_bbr", AsyncMock(return_value={"control": "cubic"}))
    monkeypatch.setattr(remote, "_issue_certificate", AsyncMock(return_value={"status": "valid", "auto_renew": True}))
    return connection


def test_install_with_null_validation_completes_only_after_login_verification(tmp_path, monkeypatch):
    connection = _wire_install(monkeypatch)
    emit = AsyncMock()
    result = asyncio.run(remote.run_remote_job(job(validation=None), "server-secret", None, emit, options(tmp_path)))
    assert result["url"] == "https://panel.example.com/abcdefghijkl/"
    assert result["password"] == "qqqzzz" and result["login_verified"] is True
    remote.backup_remote.assert_awaited_once_with(connection, "task_123", cert_domain="panel.example.com")
    remote._wait_for_panel.assert_awaited_once()
    remote.rollback_remote.assert_not_awaited()
    connection.wait_closed.assert_awaited_once()
    assert all("server-secret" not in str(args) for args in emit.call_args_list)
    assert any("rm -f -- /etc/x-ui/x-ui.db" in args.args[1] for args in remote._run.call_args_list)


def test_existing_panel_requires_explicit_overwrite_before_backup(tmp_path, monkeypatch):
    connection = _wire_install(monkeypatch, existing=True)
    with pytest.raises(remote.RemoteJobError, match="允许覆盖"):
        asyncio.run(remote.run_remote_job(job(), "secret", None, AsyncMock(), options(tmp_path)))
    remote.backup_remote.assert_not_awaited()
    connection.wait_closed.assert_awaited_once()


def test_certificate_failure_restores_snapshot_without_publishing_secrets(tmp_path, monkeypatch):
    connection = _wire_install(monkeypatch)
    remote._issue_certificate.side_effect = remote.RemoteJobError("SSL 证书申请失败。")
    emit = AsyncMock()
    with pytest.raises(remote.RemoteJobError, match="SSL"):
        asyncio.run(remote.run_remote_job(job(), "hidden", None, emit, options(tmp_path)))
    remote._remove_acme_job.assert_awaited_once()
    remote.rollback_remote.assert_awaited_once_with(connection, "/var/backups/3xui-web/task_123")
    remote._wait_for_panel.assert_not_awaited()
    assert all("hidden" not in str(args) for args in emit.call_args_list)


def test_auxiliary_cleanup_failure_cannot_skip_database_rollback(tmp_path, monkeypatch):
    connection = _wire_install(monkeypatch)
    remote._wait_for_panel.side_effect = remote.RemoteJobError("面板登录失败。")
    remote._remove_acme_job.side_effect = OSError("cron permission denied")
    remote._restore_bbr.side_effect = OSError("sysctl unsupported")
    with pytest.raises(remote.RemoteJobError, match="原面板已恢复"):
        asyncio.run(remote.run_remote_job(job(), "hidden", None, AsyncMock(), options(tmp_path)))
    remote._restore_bbr.assert_awaited_once()
    remote.rollback_remote.assert_awaited_once_with(connection, "/var/backups/3xui-web/task_123")


def test_migration_keeps_two_factor_in_the_original_database(tmp_path, monkeypatch):
    path = tmp_path / "upload.db"
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password TEXT); INSERT INTO users VALUES(1,'old-admin','old-hash'); CREATE TABLE settings(key TEXT,value TEXT); INSERT INTO settings VALUES('twoFactorEnable','true'); CREATE TABLE inbounds(port INTEGER);")
    db.commit(); db.close()
    source = job(kind="migrate", source_version="2.9.4", reset_two_factor=True)
    final_job, baseline = remote._migration_context(source, path)
    assert final_job["reset_two_factor"] is False
    assert final_job["panel_port"] == 2053
    assert final_job["panel_path"] == "/"
    assert "old-hash" not in str(baseline)
    # No SQLite handle remains open on Windows after reading the snapshot.
    path.rename(tmp_path / "closed.db")


def test_migration_returns_after_verification_and_schedules_final_reboot(tmp_path, monkeypatch):
    old_connection = _wire_install(monkeypatch)
    path = tmp_path / "upload.db"
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password TEXT); INSERT INTO users VALUES(1,'old-admin','old-hash'); CREATE TABLE settings(key TEXT,value TEXT); CREATE TABLE inbounds(port INTEGER);")
    db.commit(); db.close()
    monkeypatch.setattr(remote, "import_remote_database", AsyncMock(return_value={"warnings": [], "inbounds": 0}))
    monkeypatch.setattr(remote, "_verify_migration_counts", AsyncMock(return_value={"inbounds": 0, "clients": 0}))
    monkeypatch.setattr(remote, "_schedule_final_reboot", AsyncMock())
    result = asyncio.run(remote.run_remote_job(job(kind="migrate", source_version="2.9.4", validation={"inbounds": 0, "clients": 0}), "secret", path,
                                              AsyncMock(), options(tmp_path)))
    assert result["login_verified"] is False
    assert result["credentials_preserved"] and result["panel_access_verified"]
    remote.backup_remote.assert_awaited_once_with(old_connection, "task_123", cert_domain="panel.example.com")
    assert "username" not in result and "password" not in result
    remote._wait_for_panel.assert_awaited_once()
    remote._schedule_final_reboot.assert_awaited_once()
    assert remote._schedule_final_reboot.await_args.args[0] is old_connection
    remote._verify_bbr.assert_not_awaited()
    remote._verify_migration_counts.assert_awaited_once()
    assert result["reboot_scheduled"] is True and result["reboot_verified"] is False
    assert result["migration_counts"] == {"inbounds": 0, "clients": 0}
    old_connection.wait_closed.assert_awaited_once()


def test_migration_count_mismatch_cannot_be_successful(monkeypatch):
    monkeypatch.setattr(remote, "_run", AsyncMock(return_value=json.dumps({"inbounds": 3, "clients": 12})))
    with pytest.raises(remote.RemoteJobError, match="数量与上传数据库不一致"):
        asyncio.run(remote._verify_migration_counts(object(), job(validation={"inbounds": 3, "clients": 13})))


def _preserved_db(path, port=443, panel_path="/old/deep/"):
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password TEXT,login_epoch INTEGER);
        INSERT INTO users VALUES(1,'original-admin','original-password-hash',7);
        INSERT INTO users VALUES(2,'second-admin','second-password-hash',11);
        CREATE TABLE settings(key TEXT UNIQUE,value TEXT);
        INSERT INTO settings VALUES('twoFactorEnable','true');
        INSERT INTO settings VALUES('twoFactorToken','original-authenticator-secret');
        INSERT INTO settings VALUES('webDomain','old.example.com');
        CREATE TABLE inbounds(id INTEGER PRIMARY KEY,port INTEGER,settings TEXT,network TEXT);
        INSERT INTO inbounds VALUES(1,19000,'{"clients":[]}','tcp');
        INSERT INTO inbounds VALUES(2,443,'{"clients":[]}','udp');
    """)
    if port is not None:
        db.execute("INSERT INTO settings VALUES('webPort',?)", (str(port),))
    if panel_path is not None:
        db.execute("INSERT INTO settings VALUES('webBasePath',?)", (panel_path,))
    db.commit(); db.close()
    return path


def _local_remote_reader(monkeypatch, path, captured=None):
    async def run(conn, command, *args, **kwargs):
        if captured is not None:
            captured.append(command)
        if command.startswith("python3 -c "):
            code = shlex.split(command)[2]
            code = code.replace(repr("file:/etc/x-ui/x-ui.db?mode=ro"), repr(path.resolve().as_uri() + "?mode=ro"))
            code = code.replace(repr("/etc/x-ui/x-ui.db"), repr(str(path)))
            output = io.StringIO()
            with redirect_stdout(output):
                exec(code, {})
            return output.getvalue()
        return ""
    monkeypatch.setattr(remote, "_run", run)


def test_migration_deploys_temporary_database_before_import_and_returns_original_access(tmp_path, monkeypatch):
    connection = _wire_install(monkeypatch)
    source = _preserved_db(tmp_path / "source.db")
    source_bytes = source.read_bytes()
    task = job(kind="migrate", source_version="2.9.4", panel_port=19000,
               panel_path="/temporary_path/", reset_two_factor=True,
               validation={"inbounds": 2, "clients": 0, "panel_settings": {"port": 443, "path": "/old/deep/"}})
    original_task = copy.deepcopy(task)
    steps, received = [], []
    def mark(name, value=None):
        async def call(*args, **kwargs):
            steps.append(name)
            if len(args) > 1 and isinstance(args[1], dict):
                received.append((name, copy.deepcopy(args[1])))
            return value
        return call
    remote._install.side_effect = mark("install")
    remote._configure.side_effect = mark("temporary-configure")
    remote._verify_temporary_installation.side_effect = mark("temporary-ready")
    remote._configure_restored.side_effect = mark("restored-configure")
    remote._issue_certificate.side_effect = mark("certificate", {"status": "valid"})
    remote._wait_for_panel.side_effect = mark("final-https")
    remote._verify_preserved_migration_state.side_effect = mark("preserved")
    monkeypatch.setattr(remote, "import_remote_database", AsyncMock(side_effect=mark("import", {"inbounds": 2, "warnings": []})))
    monkeypatch.setattr(remote, "_verify_migration_counts", AsyncMock(return_value={"inbounds": 2, "clients": 0}))
    monkeypatch.setattr(remote, "_schedule_final_reboot", AsyncMock())
    result = asyncio.run(remote.run_remote_job(task, "private-ssh-password", source, AsyncMock(), options(tmp_path)))
    assert steps.index("install") < steps.index("temporary-configure") < steps.index("temporary-ready") < steps.index("import")
    assert steps.index("import") < steps.index("restored-configure") < steps.index("certificate") < steps.index("final-https")
    configured = next(value for name, value in received if name == "temporary-configure")
    assert configured["panel_port"] == 19000 and configured["listen_ip"] == "127.0.0.1"
    assert configured["reset_two_factor"] is False
    for name, value in received:
        if name in {"restored-configure", "certificate", "preserved", "final-https"}:
            assert value["panel_port"] == 443 and value["panel_path"] == "/old/deep/"
            assert value["kind"] == "migrate"
    assert [call.args[2] for call in remote._probe_port.await_args_list] == [80, 443]
    assert result["url"] == "https://panel.example.com/old/deep/"
    assert result["temporary_panel_port"] == 19000
    assert result["credentials_preserved"] and result["panel_access_verified"]
    assert result["login_verified"] is False
    assert "username" not in result and "password" not in result
    assert "original-password-hash" not in str(result) and "original-authenticator-secret" not in str(result)
    assert source.read_bytes() == source_bytes and task == original_task


@pytest.mark.parametrize("version", ["v2.9.4", "v3.4.2"])
def test_preserved_migration_only_checks_https_and_never_attempts_login(monkeypatch, version):
    seen = []
    def handler(request):
        seen.append(request)
        assert request.method == "GET"
        return httpx.Response(200, text="original panel login page")
    original = httpx.AsyncClient
    monkeypatch.setattr(remote.httpx, "AsyncClient", lambda **kwargs: original(
        **kwargs, transport=httpx.MockTransport(handler)))
    asyncio.run(remote._verify_https_login(job(kind="migrate", version=version, panel_path="/old/", panel_port=8443)))
    assert len(seen) == 1
    assert seen[0].url.path == "/old/" and seen[0].url.port == 8443
    assert seen[0].extensions["sni_hostname"] == "panel.example.com"


def test_restored_configuration_never_changes_credentials_port_path_or_two_factor(tmp_path, monkeypatch):
    source = _preserved_db(tmp_path / "source.db")
    commands = []
    _local_remote_reader(monkeypatch, source, commands)
    asyncio.run(remote._configure_restored(object(), job(kind="migrate", reset_two_factor=True)))
    assert commands[0].startswith("/usr/local/x-ui/x-ui setting -listenIP ")
    assert all(flag not in commands[0] for flag in ("-username", "-password", "-port", "-webBasePath", "-resetTwoFactor"))
    with sqlite3.connect(source) as db:
        values = dict(db.execute("SELECT key,value FROM settings"))
        assert values["webPort"] == "443" and values["webBasePath"] == "/old/deep/"
        assert values["twoFactorEnable"] == "true" and values["twoFactorToken"] == "original-authenticator-secret"
        assert values["webDomain"] == "panel.example.com"
        assert db.execute("SELECT password FROM users WHERE id=1").fetchone()[0] == "original-password-hash"


@pytest.mark.parametrize("mutation", [
    "UPDATE users SET password='changed' WHERE id=1",
    "UPDATE users SET username='changed' WHERE id=2",
    "UPDATE settings SET value='changed' WHERE key='twoFactorToken'",
    "UPDATE settings SET value='false' WHERE key='twoFactorEnable'",
    "UPDATE settings SET value='8443' WHERE key='webPort'",
    "UPDATE settings SET value='/changed/' WHERE key='webBasePath'",
    "UPDATE inbounds SET port=2443 WHERE id=2",
])
def test_migration_state_verification_detects_any_protected_state_change(tmp_path, monkeypatch, mutation):
    source = _preserved_db(tmp_path / "source.db")
    task = job(kind="migrate", source_version="2.9.4")
    final_job, baseline = remote._migration_context(task, source)
    assert "original-password-hash" not in str(baseline)
    assert "original-authenticator-secret" not in str(baseline)
    target = tmp_path / "target.db"
    target.write_bytes(source.read_bytes())
    _local_remote_reader(monkeypatch, target)
    asyncio.run(remote._verify_preserved_migration_state(object(), final_job, baseline))
    with sqlite3.connect(target) as db:
        db.execute(mutation)
    with pytest.raises(remote.RemoteJobError, match="发生变化"):
        asyncio.run(remote._verify_preserved_migration_state(object(), final_job, baseline))


@pytest.mark.parametrize("port", [80, 22, 2222])
def test_unsupported_original_ports_fail_before_ssh_without_overriding_them(tmp_path, monkeypatch, port):
    source = _preserved_db(tmp_path / "source.db", port=port)
    connect = AsyncMock()
    monkeypatch.setattr(remote, "_connect", connect)
    task = job(kind="migrate", source_version="2.9.4", panel_port=19000, ssh_port=2222)
    with pytest.raises(remote.RemoteJobError, match="原数据库的面板端口"):
        asyncio.run(remote.run_remote_job(task, "private-ssh-password", source, AsyncMock(), options(tmp_path)))
    connect.assert_not_awaited()


@pytest.mark.parametrize("old_path,expected", [(None, "/"), ("/x/", "/x/"), ("old/deep", "/old/deep/")])
def test_migration_default_port_and_old_short_root_or_nested_path_are_preserved(tmp_path, old_path, expected):
    source = _preserved_db(tmp_path / "source.db", port=None, panel_path=old_path)
    task = job(kind="migrate", source_version="2.9.4", panel_port=19000)
    final_job, _ = remote._migration_context(task, source)
    assert final_job["panel_port"] == 2053 and final_job["panel_path"] == expected
    assert task["panel_port"] == 19000


def test_progress_identifies_pending_dns_ssh_and_environment_checks(tmp_path, monkeypatch):
    async def scenario():
        connection = _wire_install(monkeypatch)
        events = []
        dns_started, release_dns = asyncio.Event(), asyncio.Event()
        ssh_started, release_ssh = asyncio.Event(), asyncio.Event()
        environment_started, release_environment = asyncio.Event(), asyncio.Event()

        async def emit(stage, message):
            events.append((stage, message))

        async def dns(*args):
            dns_started.set()
            await release_dns.wait()

        async def connect(*args):
            ssh_started.set()
            await release_ssh.wait()
            return connection

        async def run(conn, command, **kwargs):
            if command == remote._python(remote._PREFLIGHT):
                environment_started.set()
                await release_environment.wait()
                return json.dumps({"existing": False})
            return ""

        monkeypatch.setattr(remote, "_check_dns", dns)
        monkeypatch.setattr(remote, "_connect", connect)
        monkeypatch.setattr(remote, "_run", run)
        task = asyncio.create_task(remote.run_remote_job(job(), "private-ssh-password", None, emit, options(tmp_path)))
        await asyncio.wait_for(dns_started.wait(), 2)
        assert events[-1] == ("dns", "正在检查域名解析是否仅指向目标服务器。")
        release_dns.set()
        await asyncio.wait_for(ssh_started.wait(), 2)
        assert events[-1][0] == "connect" and "正在连接" in events[-1][1]
        assert any(stage == "dns" and "已通过" in message for stage, message in events)
        release_ssh.set()
        await asyncio.wait_for(environment_started.wait(), 2)
        assert events[-1][0] == "preflight" and "正在检查" in events[-1][1]
        assert any(stage == "connect" and "已通过" in message for stage, message in events)
        release_environment.set()
        await asyncio.wait_for(task, 2)
        assert "private-ssh-password" not in str(events)
        for stage in ("dns", "connect", "preflight", "ports", "backup", "configure", "certificate", "bbr", "restart", "verify", "cleanup"):
            assert sum(event_stage == stage for event_stage, _ in events) >= 2

    asyncio.run(scenario())


def test_failed_dns_check_never_emits_passed_or_attempts_ssh(tmp_path, monkeypatch):
    _wire_install(monkeypatch)
    remote._check_dns.side_effect = remote.RemoteJobError("域名尚未解析。")
    emit = AsyncMock()
    with pytest.raises(remote.RemoteJobError, match="尚未解析"):
        asyncio.run(remote.run_remote_job(job(), "private-ssh-password", None, emit, options(tmp_path)))
    assert [call.args[0] for call in emit.await_args_list] == ["dns"]
    remote._connect.assert_not_awaited()


def test_installer_logs_download_and_version_boundaries_without_shell_output(tmp_path, monkeypatch):
    source = b"install_x_ui() {\n    config_after_install\n            systemctl start x-ui\n}\n"
    monkeypatch.setitem(remote.INSTALLER_SHA256, "v2.9.4", hashlib.sha256(source).hexdigest())
    events = []

    async def emit(stage, message):
        events.append((stage, message))

    def forbidden_local_download(*args, **kwargs):
        raise AssertionError("Installer download must use the target server SSH connection")

    monkeypatch.setattr(remote.httpx, "AsyncClient", forbidden_local_download)

    async def run(conn, command, *args, **kwargs):
        if "urllib.request" in command:
            assert events[-1][0] == "download" and "目标服务器" in events[-1][1]
            return base64.b64encode(source).decode()
        if "bash " in command:
            assert events[-1][0] == "install" and "正在安装" in events[-1][1]
            return "private-installer-password"
        return "2.9.4\nprivate-installer-password" if command.endswith("x-ui -v") else ""

    monkeypatch.setattr(remote, "_run", run)
    asyncio.run(remote._install(object(), job(), options(tmp_path), emit))
    assert [stage for stage, _ in events] == ["download", "download", "install", "install", "install"]
    assert "已通过" in events[-1][1]
    assert "private-installer-password" not in str(events)


def test_installer_download_timeout_identifies_target_and_stops_before_install(tmp_path):
    conn = SimpleNamespace(run=AsyncMock(side_effect=asyncio.TimeoutError("private-download-output")))
    emit = AsyncMock()
    with pytest.raises(remote.RemoteJobError, match="目标服务器无法下载官方安装脚本") as error:
        asyncio.run(remote._install(conn, job(), options(tmp_path), emit))
    assert "private-download-output" not in str(error.value)
    assert [call.args[0] for call in emit.await_args_list] == ["download"]
    conn.run.assert_awaited_once()
    call = conn.run.await_args
    assert call.kwargs["check"] is True and call.kwargs["timeout"] == 60
    assert "urllib.request" in call.args[0]
    assert "bash " not in call.args[0]


def test_target_installer_download_reads_only_size_limit_plus_one(monkeypatch):
    read_sizes = []

    class OversizedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            read_sizes.append(size)
            return b"x" * size

    def urlopen(request, timeout):
        assert request.full_url == "https://raw.githubusercontent.com/mhsanaei/3x-ui/v2.9.4/install.sh"
        assert timeout == 45
        return OversizedResponse()

    async def run(conn, command, **kwargs):
        code = shlex.split(command)[2]
        compile(code, "target-installer-download", "exec")
        output = io.StringIO()
        with redirect_stdout(output):
            exec(code, {})
        return output.getvalue()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(remote, "_run", run)
    with pytest.raises(remote.RemoteJobError, match="体积异常"):
        asyncio.run(remote._download_installer(object(), "v2.9.4"))
    assert read_sizes == [remote.MAX_INSTALLER_BYTES + 1]


def test_installer_download_hash_change_prevents_execution(tmp_path):
    tampered = b"untrusted-installer-must-not-appear-in-errors"
    conn = SimpleNamespace(run=AsyncMock(return_value=SimpleNamespace(stdout=base64.b64encode(tampered).decode())))
    emit = AsyncMock()
    with pytest.raises(remote.RemoteJobError, match="不一致") as error:
        asyncio.run(remote._install(conn, job(), options(tmp_path), emit))
    conn.run.assert_awaited_once()
    assert [call.args[0] for call in emit.await_args_list] == ["download"]
    assert tampered.decode() not in str(error.value) + str(emit.await_args_list)


@pytest.mark.parametrize("response", [
    "A" * ((((remote.MAX_INSTALLER_BYTES + 2) // 3) * 4) + 4),
    "invalid-private-download-data?",
])
def test_invalid_installer_download_transport_is_bounded_and_not_echoed(response):
    conn = SimpleNamespace(run=AsyncMock(return_value=SimpleNamespace(stdout=response)))
    with pytest.raises(remote.RemoteJobError) as error:
        asyncio.run(remote._download_installer(conn, "v2.9.4"))
    assert response not in str(error.value)


def test_installer_download_rejects_non_allowlisted_version_before_ssh():
    conn = SimpleNamespace(run=AsyncMock())
    with pytest.raises(remote.RemoteJobError, match="不受支持"):
        asyncio.run(remote._download_installer(conn, "main;reboot"))
    conn.run.assert_not_awaited()

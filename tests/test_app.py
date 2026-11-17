import asyncio
import io
import json
import os
import re
import shutil
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import hash_password, validate_domain, validate_target, verify_password

ADMIN_PASSWORD = "test-only-admin-password"


@pytest.fixture
def console(tmp_path, monkeypatch):
    settings = Settings(secret="test-only-secret-" * 4, data_dir=tmp_path, cookie_secure=False, allowed_hosts=("testserver",), enable_worker=False)
    app = create_app(settings)
    # These route tests hold jobs in the queue intentionally. Worker lifecycle
    # and unavailable execution are covered separately without this ready stub.
    monkeypatch.setattr(app.state.worker, "runtime_status", lambda: {"enabled": True, "available": True, "state": "running", "message": "执行器已就绪。", "active_jobs": 0, "capacity": 2})
    app.state.store.add_user("admin", hash_password(ADMIN_PASSWORD), "admin")
    with TestClient(app) as client:
        yield app, client


def login(client, username="admin", password=ADMIN_PASSWORD):
    token = client.get("/api/me").json()["csrf_token"]
    response = client.post("/api/login", json={"username": username, "password": password}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def task_data(**kwargs):
    return {"kind": "install", "server_ip": "8.8.8.8", "ssh_port": "22", "ssh_username": "root", "ssh_password": "test-only-ssh-password", "domain": "panel.example.com", "version": "v2.9.4", "custom_panel_port": "true", "panel_port": "443", **kwargs}


def sample_db(path):
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password TEXT); CREATE TABLE settings(key TEXT,value TEXT); CREATE TABLE inbounds(id INTEGER PRIMARY KEY,settings TEXT,stream_settings TEXT);")
        db.execute("INSERT INTO users VALUES(1,'old-admin','old-hash')")
        db.executemany("INSERT INTO settings VALUES(?,?)", [("webPort", "18443"), ("webBasePath", "/old-panel/")])
        db.execute("INSERT INTO inbounds VALUES(1,?,?)", ('{"clients":[{"id":"example"}]}', '{}'))
    return path.read_bytes()


def test_login_csrf_and_no_open_registration(console):
    app, client = console
    assert client.get("/").status_code == 200
    assert client.get("/api/tasks").status_code == 401
    assert client.post("/api/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 403
    headers = login(client)
    assert client.get("/api/me").json()["user"]["role"] == "admin"
    assert client.get("/api/me").headers["cache-control"] == "no-store"
    assert client.post("/api/register", json={}).status_code == 404
    assert client.post("/api/logout", headers=headers).status_code == 200
    assert client.get("/api/tasks").status_code == 401


@pytest.mark.parametrize("asset", ["app.js", "style.css"])
def test_frontend_content_changes_get_new_urls_even_with_same_file_metadata(tmp_path, monkeypatch, asset):
    from app import main

    root = tmp_path / "frontend"
    shutil.copytree(main.ROOT / "templates", root / "templates")
    shutil.copytree(main.ROOT / "static", root / "static")
    monkeypatch.setattr(main, "ROOT", root)
    settings = Settings(secret="frontend-cache-test-" * 3, data_dir=tmp_path / "data", cookie_secure=False, allowed_hosts=("testserver",), enable_worker=False)
    app = create_app(settings)
    with TestClient(app) as client:
        first_page = client.get("/")
        assert first_page.headers["cache-control"] == "no-store"
        pattern = rf'/static/{re.escape(asset)}\?v=[a-f0-9]+'
        old_url = re.search(pattern, first_page.text).group()
        old_response = client.get(old_url)
        assert old_response.status_code == 200
        assert old_response.headers["cache-control"] == "no-cache, must-revalidate"
        path = root / "static" / asset
        metadata = path.stat()
        content = path.read_bytes()
        # Same size and timestamp must still change the URL: stat-based cache
        # keys alone caused a new template to load an obsolete cached script.
        path.write_bytes(bytes([content[0] ^ 1]) + content[1:])
        os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        second_page = client.get("/")
        new_url = re.search(pattern, second_page.text).group()
        assert new_url != old_url
        refreshed = client.get(new_url)
        assert refreshed.status_code == 200
        assert refreshed.content != old_response.content
        assert refreshed.headers["cache-control"] == "no-cache, must-revalidate"
        assert second_page.headers["cache-control"] == "no-store"


def test_customer_isolation_and_disable(console):
    app, client = console
    headers = login(client)
    for name in ("alice", "bob"):
        response = client.post("/api/admin/users", json={"username": name, "password": "customer-test-password"}, headers=headers)
        assert response.status_code == 201
    alice_headers = login(client, "alice", "customer-test-password")
    created = client.post("/api/tasks", data=task_data(), headers=alice_headers)
    assert created.status_code == 201, created.text
    task = created.json()["task"]
    assert "encrypted_password" not in task and "upload_path" not in task
    assert "test-only-ssh-password" not in created.text
    login(client, "bob", "customer-test-password")
    assert client.get(f"/api/tasks/{task['id']}").status_code == 404
    assert client.get("/api/tasks").json()["tasks"] == []
    assert client.get("/api/admin/users").status_code == 403
    headers = login(client)
    alice = app.state.store.user_by_name("alice")
    assert client.patch(f"/api/admin/users/{alice['id']}", json={"active": False}, headers=headers).status_code == 200
    assert not app.state.store.user(alice["id"])["active"]


def test_target_validation_and_server_lock(console):
    app, client = console
    headers = login(client)
    for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "metadata.google.internal"):
        response = client.post("/api/tasks", data=task_data(server_ip=ip), headers=headers)
        assert response.status_code == 422
    assert client.post("/api/tasks", data=task_data(domain="x;touch /tmp/oops"), headers=headers).status_code == 422
    assert client.post("/api/tasks", data=task_data(panel_port="80"), headers=headers).status_code == 422
    assert client.post("/api/tasks", data=task_data(), headers=headers).status_code == 201
    assert client.post("/api/tasks", data=task_data(), headers=headers).status_code == 409
    queued = app.state.store.tasks(None)[0]
    assert queued["encrypted_password"] != "test-only-ssh-password"
    assert queued["panel_path"].startswith("/") and len(queued["panel_path"]) > 25


def test_database_upload_and_no_cross_version(console, tmp_path):
    app, client = console
    headers = login(client)
    data = task_data(kind="migrate", source_version="v2.9.4")
    bad = client.post("/api/tasks", data=data, files={"database": ("x-ui.db", b"not sqlite")}, headers=headers)
    assert bad.status_code == 422
    assert not list((tmp_path / "uploads").glob("*.db"))
    content = sample_db(tmp_path / "sample.db")
    cross = client.post("/api/tasks", data={**data, "version": "v3.4.2"}, files={"database": ("x-ui.db", content)}, headers=headers)
    assert cross.status_code == 422
    good = client.post("/api/tasks", data=data, files={"database": ("../../x-ui.db", content)}, headers=headers)
    assert good.status_code == 201, good.text
    task = good.json()["task"]
    assert task["validation"]["inbounds"] == 1
    assert task["validation"]["clients"] == 1
    assert len(list((tmp_path / "uploads").glob("*.db"))) == 1


@pytest.mark.parametrize("empty_tables", [
    ("clients",), ("client_inbounds",), ("clients", "client_inbounds"),
])
def test_v294_upload_accepts_empty_residual_client_tables_and_counts_inbound_json(console, tmp_path, empty_tables):
    app, client = console
    headers = login(client)
    source = tmp_path / "empty-residual-tables.db"
    sample_db(source)
    with sqlite3.connect(source) as db:
        if "clients" in empty_tables:
            db.execute("CREATE TABLE clients(id INTEGER PRIMARY KEY,email TEXT)")
        if "client_inbounds" in empty_tables:
            db.execute("CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER)")
    before = source.read_bytes()
    response = client.post("/api/tasks", data=task_data(kind="migrate", source_version="v2.9.4"),
                           files={"database": ("x-ui.db", before)}, headers=headers)
    assert response.status_code == 201, response.text
    task = response.json()["task"]
    assert task["status"] == "queued"
    assert task["validation"]["inbounds"] == 1
    assert task["validation"]["clients"] == 1
    assert task["validation"]["client_count_kind"] == "入站客户条目"
    assert any("空的独立客户数据表" in warning for warning in task["validation"]["warnings"])
    saved = app.state.store.task(task["id"])
    assert len(app.state.store.tasks(None)) == 1
    assert Path(saved["upload_path"]).read_bytes() == before
    assert source.read_bytes() == before


@pytest.mark.parametrize("populated_table", ["clients", "client_inbounds"])
def test_v294_upload_rejects_independent_clients_or_orphan_links_without_retaining_upload(console, tmp_path, populated_table):
    app, client = console
    headers = login(client)
    source = tmp_path / "independent-clients.db"
    sample_db(source)
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE clients(id INTEGER PRIMARY KEY,email TEXT)")
        db.execute("CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER)")
        if populated_table == "clients":
            db.execute("INSERT INTO clients VALUES(1,'test-only-independent-client')")
        else:
            # The table can have relationships even when its clients are absent.
            db.execute("INSERT INTO client_inbounds VALUES(99,1)")
    before = source.read_bytes()
    response = client.post("/api/tasks", data=task_data(kind="migrate", source_version="v2.9.4"),
                           files={"database": ("x-ui.db", before)}, headers=headers)
    assert response.status_code == 422
    assert "不能确认这些独立记录也能恢复" in response.json()["detail"]
    assert "数据库包含 3.x 客户数据表" not in response.text
    assert "test-only-independent-client" not in response.text
    assert "test-only-ssh-password" not in response.text
    assert app.state.store.tasks(None) == []
    assert not list((app.state.settings.data_dir / "uploads").glob("*.db"))
    assert source.read_bytes() == before


def test_retry_requires_fresh_password_and_clears_old_secret(console):
    app, client = console
    headers = login(client)
    created = client.post("/api/tasks", data=task_data(), headers=headers).json()["task"]
    app.state.store.finish(created["id"], error="SSH 无法连接")
    assert app.state.store.task(created["id"])["encrypted_password"] is None
    assert client.post(f"/api/tasks/{created['id']}/retry", json={}, headers=headers).status_code == 422
    retried = client.post(f"/api/tasks/{created['id']}/retry", json={"ssh_password": "fresh-test-only"}, headers=headers)
    assert retried.status_code == 201
    assert retried.json()["task"]["id"] != created["id"]
    assert "fresh-test-only" not in retried.text


def test_default_port_is_random_and_hidden_port_field_is_ignored(console):
    app, client = console
    headers = login(client)
    data = task_data(panel_port="80")
    data.pop("custom_panel_port")
    response = client.post("/api/tasks", data=data, headers=headers)
    assert response.status_code == 201, response.text
    task = response.json()["task"]
    assert task["custom_panel_port"] == 0
    assert 10000 <= task["panel_port"] <= 60000
    assert task["panel_port"] not in {22, 80}


@pytest.mark.parametrize("port", ["", "not-a-port", "0", "65536", "80", "22"])
def test_custom_port_requires_a_valid_explicit_value(console, port):
    _, client = console
    headers = login(client)
    response = client.post("/api/tasks", data=task_data(panel_port=port), headers=headers)
    assert response.status_code == 422


def test_custom_port_is_used_only_when_checked(console):
    _, client = console
    headers = login(client)
    response = client.post("/api/tasks", data=task_data(panel_port="15443"), headers=headers)
    assert response.status_code == 201, response.text
    assert response.json()["task"]["panel_port"] == 15443
    assert response.json()["task"]["custom_panel_port"] == 1


def test_migration_keeps_source_settings_and_two_factor_without_reset(console, tmp_path):
    app, client = console
    headers = login(client)
    source = tmp_path / "source-2fa.db"
    sample_db(source)
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO settings VALUES('twoFactorEnable','true')")
    before = source.read_bytes()
    response = client.post("/api/tasks", data=task_data(kind="migrate", source_version="v2.9.4", custom_panel_port="false", reset_two_factor="true"), files={"database": ("x-ui.db", before)}, headers=headers)
    assert response.status_code == 201, response.text
    task = response.json()["task"]
    assert task["validation"]["panel_settings"] == {"port": 18443, "path": "/old-panel/"}
    assert task["validation"]["two_factor_enabled"] is True
    assert task["reset_two_factor"] == 0
    assert task["panel_port"] != 18443
    assert task["custom_panel_port"] == 0
    assert "old-hash" not in response.text
    assert Path(app.state.store.task(task["id"])["upload_path"]).read_bytes() == before


def test_retry_revalidates_database_and_preserves_port_mode(console, tmp_path):
    app, client = console
    headers = login(client)
    response = client.post("/api/tasks", data=task_data(kind="migrate", source_version="v2.9.4", custom_panel_port="false"), files={"database": ("x-ui.db", sample_db(tmp_path / "retry-source.db"))}, headers=headers)
    assert response.status_code == 201, response.text
    original = response.json()["task"]
    app.state.store.finish(original["id"], error="SSH connection interrupted")
    # A task created by an earlier release may not have source panel metadata.
    with app.state.store.connect() as db:
        db.execute("UPDATE tasks SET validation=?,reset_two_factor=1 WHERE id=?", ('{"inbounds":1,"clients":1}', original["id"]))
    retry = client.post(f"/api/tasks/{original['id']}/retry", json={"ssh_password": "fresh-test-password"}, headers=headers)
    assert retry.status_code == 201, retry.text
    task = retry.json()["task"]
    assert task["validation"]["panel_settings"]["port"] == 18443
    assert task["custom_panel_port"] == 0 and task["reset_two_factor"] == 0
    assert task["panel_port"] != 18443
    assert task["panel_port"] == original["panel_port"]


def test_migration_rejects_source_panel_port_conflicting_with_ssh(console, tmp_path):
    app, client = console
    headers = login(client)
    source = tmp_path / "source-ssh-conflict.db"
    sample_db(source)
    with sqlite3.connect(source) as db:
        db.execute("UPDATE settings SET value='2222' WHERE key='webPort'")
    response = client.post("/api/tasks", data=task_data(kind="migrate", source_version="v2.9.4", ssh_port="2222", custom_panel_port="false"), files={"database": ("x-ui.db", source.read_bytes())}, headers=headers)
    assert response.status_code == 422
    assert app.state.store.tasks(None) == []
    assert not list((app.state.settings.data_dir / "uploads").glob("*.db"))


def test_process_restart_marks_interrupted_instead_of_replaying(console):
    app, client = console
    headers = login(client)
    task = client.post("/api/tasks", data=task_data(), headers=headers).json()["task"]
    app.state.store.claim()
    app.state.store.interrupt_running()
    interrupted = app.state.store.task(task["id"])
    assert interrupted["status"] == "interrupted"
    assert interrupted["encrypted_password"] is None
    assert app.state.store.claim() is None


def test_password_reset_revokes_existing_session(console):
    app, client = console
    login(client)
    with app.state.store.connect() as db:
        db.execute("UPDATE users SET session_version=session_version+1 WHERE username='admin'")
    assert client.get("/api/tasks").status_code == 401


def test_validation_never_echoes_password(console):
    app, client = console
    headers = login(client)
    value = "sensitive-" * 100
    response = client.post("/api/admin/users", json={"username": "abc", "password": value}, headers=headers)
    assert response.status_code == 422
    assert value not in response.text


def test_disabled_then_reenabled_customer_cannot_reuse_cookie(console):
    app, client = console
    user = app.state.store.add_user("alice", hash_password("customer-test-password"))
    login(client, "alice", "customer-test-password")
    app.state.store.set_user_active(user["id"], False)
    app.state.store.set_user_active(user["id"], True)
    assert client.get("/api/tasks").status_code == 401


def test_oversized_request_rejected_before_parsing(console):
    app, client = console
    headers = login(client)
    response = client.post("/api/tasks", content=b"", headers={**headers, "Content-Length": str(53 * 1024 * 1024)})
    assert response.status_code == 413


@pytest.mark.parametrize("fail", [False, True])
def test_worker_persists_result_and_wipes_secret(console, monkeypatch, fail):
    from app import remote

    app, client = console
    headers = login(client)
    task = client.post("/api/tasks", data=task_data(), headers=headers).json()["task"]

    async def fake_run(job, password, upload, emit, options):
        assert password == "test-only-ssh-password"
        await emit("preflight", "test-only-ssh-password should be redacted")
        if fail:
            raise RuntimeError("Connection failed: test-only-ssh-password")
        return {"url": "https://panel.example.com/path/", "username": "qqqzzz", "password": "qqqzzz"}

    monkeypatch.setattr(remote, "run_remote_job", fake_run)

    async def run():
        running = asyncio.create_task(app.state.worker.loop())
        try:
            async def done():
                while app.state.store.task(task["id"])["status"] in {"queued", "running"}:
                    await asyncio.sleep(0.01)
            await asyncio.wait_for(done(), 3)
        finally:
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)

    asyncio.run(run())
    stored = app.state.store.task(task["id"])
    assert stored["status"] == ("failed" if fail else "succeeded")
    assert stored["encrypted_password"] is None
    detail = client.get(f"/api/tasks/{task['id']}")
    assert "test-only-ssh-password" not in detail.text
    if not fail:
        assert detail.json()["task"]["result"]["url"] == "https://panel.example.com/path/"


def test_domain_and_password_helpers():
    assert validate_domain(" PANEL.Example.COM. ") == "panel.example.com"
    for bad in ("https://a.example.com", "a.example.com:443", "a.example.com/", "127.0.0.1", "a\n.example.com"):
        with pytest.raises(ValueError):
            validate_domain(bad)
    hashed = hash_password("long-test-only-password")
    assert verify_password("long-test-only-password", hashed)
    assert not verify_password("wrong", hashed)
    assert hashed != hash_password("long-test-only-password")


def test_only_one_worker_can_own_a_data_directory(console):
    from app.worker import JobWorker

    app, _ = console

    async def run():
        first = app.state.worker
        second = JobWorker(app.state.store, app.state.settings)
        await first.start()
        try:
            with pytest.raises(RuntimeError, match="Uvicorn"):
                await second.start()
        finally:
            await first.stop()

    asyncio.run(run())


def test_disabled_worker_rejects_submission_without_saving_password(tmp_path):
    settings = Settings(secret="disabled-worker-test-" * 3, data_dir=tmp_path, cookie_secure=False, allowed_hosts=("testserver",), enable_worker=False)
    app = create_app(settings)
    app.state.store.add_user("admin", hash_password(ADMIN_PASSWORD), "admin")
    with TestClient(app) as client:
        headers = login(client)
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["execution"]["available"] is False
        assert health.json()["execution"]["state"] == "disabled"
        assert client.get("/api/ready").status_code == 503
        assert client.get("/api/me").json()["execution"]["available"] is False
        response = client.post("/api/tasks", data=task_data(), headers=headers)
        assert response.status_code == 503
        assert "未创建任务" in response.json()["detail"]
        assert app.state.store.tasks(None) == []
        assert not list((tmp_path / "uploads").glob("*.db"))


def test_failed_worker_rejects_retry_and_queue_explains_reason(console, monkeypatch):
    app, client = console
    headers = login(client)
    task = client.post("/api/tasks", data=task_data(), headers=headers).json()["task"]
    unavailable = {"enabled": True, "available": False, "state": "failed", "message": "后台任务执行器异常，暂时无法执行。", "active_jobs": 0, "capacity": 0}
    monkeypatch.setattr(app.state.worker, "runtime_status", lambda: unavailable)
    detail = client.get(f"/api/tasks/{task['id']}").json()
    assert detail["execution"]["state"] == "failed"
    assert detail["task"]["queue_info"]["position"] == 1
    assert "尚未开始执行" in detail["task"]["queue_info"]["message"]
    app.state.store.finish(task["id"], error="前一次失败")
    response = client.post(f"/api/tasks/{task['id']}/retry", json={"ssh_password": "fresh-private-password"}, headers=headers)
    assert response.status_code == 503
    assert len(app.state.store.tasks(None)) == 1
    assert "fresh-private-password" not in response.text


def test_queue_position_capacity_and_wait_are_reported(console, monkeypatch):
    app, client = console
    headers = login(client)
    first = client.post("/api/tasks", data=task_data(), headers=headers).json()["task"]
    second = client.post("/api/tasks", data=task_data(server_ip="1.1.1.1"), headers=headers).json()["task"]
    detail = client.get(f"/api/tasks/{second['id']}").json()
    assert detail["task"]["queue_info"]["position"] == 2
    assert detail["task"]["queue_info"]["wait_seconds"] >= 0
    app.state.store.claim()
    busy = {"enabled": True, "available": True, "state": "running", "message": "执行器正常。", "active_jobs": 1, "capacity": 1}
    monkeypatch.setattr(app.state.worker, "runtime_status", lambda: busy)
    queued = client.get(f"/api/tasks/{second['id']}").json()["task"]["queue_info"]
    assert queued["position"] == 1
    assert "1/1" in queued["message"]
    assert client.get("/api/tasks").json()["execution"] == busy

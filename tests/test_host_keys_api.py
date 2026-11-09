"""Task-owner and administrator SSH pin rotation with temporary keys."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import asyncssh
from fastapi.testclient import TestClient
import pytest

from app.config import Settings
from app.main import create_app
from app import main as main_module, remote
from app.security import hash_password, secret_box


TEST_PASSWORD = "test-only-host-key-admin-password"


def login(client, username="admin") -> dict:
    token = client.get("/api/me").json()["csrf_token"]
    response = client.post("/api/login", json={"username": username, "password": TEST_PASSWORD}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def add_task(app, *, host="8.8.8.8", port=2222, status="failed", user_id=None):
    user_id = user_id or app.state.store.user_by_name("admin")["id"]
    task = app.state.store.create_task({
        "id": uuid.uuid4().hex,
        "user_id": user_id,
        "kind": "install",
        "server_ip": host,
        "ssh_port": port,
        "ssh_username": "root",
        "domain": "panel.example.com",
        "version": "v2.9.4",
        "panel_port": 443,
        "panel_path": "/host-key-test-entry/",
        "source_version": None,
        "overwrite_existing": False,
        "reset_two_factor": False,
        "encrypted_password": None,
        "upload_path": None,
        "validation": None,
    })
    if status == "failed":
        app.state.store.finish(task["id"], error="服务器 SSH 指纹已变化。")
    elif status == "succeeded":
        app.state.store.finish(task["id"], result={"url": "https://panel.example.com/host-key-test-entry/"})
    elif status == "interrupted":
        with app.state.store.connect() as db:
            db.execute("UPDATE tasks SET status='interrupted',stage='interrupted' WHERE id=?", (task["id"],))
    elif status == "running":
        with app.state.store.connect() as db:
            db.execute("UPDATE tasks SET status='running',stage='connect' WHERE id=?", (task["id"],))
    return app.state.store.task(task["id"])


@pytest.fixture
def host_key_console(tmp_path, monkeypatch):
    settings = Settings(secret="host-key-test-secret-" * 3, data_dir=tmp_path, cookie_secure=False,
                        allowed_hosts=("testserver",), enable_worker=False)
    app = create_app(settings)
    for name, role in (("admin", "admin"), ("second-admin", "admin"), ("customer", "customer"), ("second-customer", "customer")):
        app.state.store.add_user(name, hash_password(TEST_PASSWORD), role)
    old_key, new_key, next_key = [asyncssh.generate_private_key("ssh-ed25519") for _ in range(3)]
    known_hosts = tmp_path / "ssh" / "known_hosts"
    remote._record_host_key(known_hosts, "8.8.8.8", 2222, old_key)
    remote._record_host_key(known_hosts, "8.8.8.8", 22, next_key)
    remote._record_host_key(known_hosts, "1.1.1.1", 2222, next_key)
    task = add_task(app)
    probe = AsyncMock(return_value=new_key.export_public_key("openssh").decode().strip())
    monkeypatch.setattr(main_module, "probe_host_key", probe, raising=False)
    with TestClient(app) as client:
        yield SimpleNamespace(app=app, client=client, task=task, path=known_hosts,
                              old_key=old_key, new_key=new_key, next_key=next_key,
                              probe=probe,
                              url=f"/api/tasks/{task['id']}/ssh-host-key")


def test_host_key_api_requires_login(host_key_console):
    console = host_key_console
    assert console.client.get(console.url).status_code == 401
    anonymous_csrf = console.client.get("/api/me").json()["csrf_token"]
    response = console.client.post(console.url, json={"confirmation_token": "test-only-invalid-confirmation-token"},
                                   headers={"X-CSRF-Token": anonymous_csrf})
    assert response.status_code == 401


def test_customer_cannot_access_admin_task_and_confirmation_requires_csrf(host_key_console):
    console = host_key_console
    headers = login(console.client, "customer")
    assert console.client.get(console.url).status_code == 404
    assert console.client.post(console.url, json={"confirmation_token": "test-only-invalid-confirmation-token"}, headers=headers).status_code == 404
    login(console.client)
    assert console.client.post(console.url, json={"confirmation_token": "test-only-invalid-confirmation-token"}).status_code == 403
    console.probe.assert_not_awaited()


def preview(console):
    response = console.client.get(console.url)
    assert response.status_code == 200, response.text
    return response.json()


def confirm(console, headers, token):
    return console.client.post(console.url, json={"confirmation_token": token}, headers=headers)


def fingerprint(key):
    return key.get_fingerprint("sha256")


def test_administrator_can_preview_and_confirm_only_target_pin_with_audit(host_key_console):
    console = host_key_console
    headers = login(console.client)
    before = console.path.read_text()
    unrelated = [line for line in before.splitlines() if not line.startswith("[8.8.8.8]:2222 ")]
    details = preview(console)
    assert details["host"] == "8.8.8.8" and details["port"] == 2222
    assert details["changed"] is True
    assert details["stored_fingerprints"] == [{"algorithm": "ssh-ed25519", "fingerprint": fingerprint(console.old_key)}]
    assert details["observed"] == {"algorithm": "ssh-ed25519", "fingerprint": fingerprint(console.new_key)}
    assert isinstance(details["confirmation_token"], str) and details["confirmation_token"]
    assert console.path.read_text() == before
    assert console.app.state.store.task(console.task["id"])["encrypted_password"] is None
    response = confirm(console, headers, details["confirmation_token"])
    assert response.status_code == 200, response.text
    after = console.path.read_text().splitlines()
    assert [line for line in after if not line.startswith("[8.8.8.8]:2222 ")] == unrelated
    target = [line for line in after if line.startswith("[8.8.8.8]:2222 ")]
    assert target == ["[8.8.8.8]:2222 " + console.new_key.export_public_key("openssh").decode().strip()]
    assert console.probe.await_count == 2
    assert all(call.args == ("8.8.8.8", 2222) for call in console.probe.await_args_list)
    events = console.app.state.store.events(console.task["id"])
    messages = "\n".join(event["message"] for event in events)
    for value in ("admin", "8.8.8.8:2222", fingerprint(console.old_key), fingerprint(console.new_key)):
        assert value in messages
    assert console.app.state.store.task(console.task["id"])["status"] == "failed"
    assert "password" not in response.text.lower()


def test_customer_can_confirm_own_task_and_audit_records_customer_role(host_key_console):
    console = host_key_console
    customer = console.app.state.store.user_by_name("customer")
    console.task = add_task(console.app, user_id=customer["id"])
    console.url = f"/api/tasks/{console.task['id']}/ssh-host-key"
    headers = login(console.client, "customer")
    before = console.path.read_text().splitlines()
    details = preview(console)
    assert details["changed"] is True and details["confirmation_token"]
    assert details["stored_fingerprints"][0]["fingerprint"] == fingerprint(console.old_key)
    assert details["observed"]["fingerprint"] == fingerprint(console.new_key)
    assert confirm(console, {}, details["confirmation_token"]).status_code == 403
    response = confirm(console, headers, details["confirmation_token"])
    assert response.status_code == 200, response.text
    after = console.path.read_text().splitlines()
    unrelated = lambda lines: [line for line in lines if not line.startswith("[8.8.8.8]:2222 ")]
    assert unrelated(after) == unrelated(before)
    assert [line for line in after if line.startswith("[8.8.8.8]:2222 ")] == [
        "[8.8.8.8]:2222 " + console.new_key.export_public_key("openssh").decode().strip()
    ]
    audit = console.app.state.store.events(console.task["id"])[-1]["message"]
    assert "客户 customer" in audit and "管理员 customer" not in audit
    assert fingerprint(console.old_key) in audit and fingerprint(console.new_key) in audit
    assert console.app.state.store.task(console.task["id"])["status"] == "failed"
    assert console.app.state.store.task(console.task["id"])["encrypted_password"] is None


def test_customer_rotation_is_isolated_from_other_customers_and_tokens(host_key_console):
    console = host_key_console
    first = console.app.state.store.user_by_name("customer")
    second = console.app.state.store.user_by_name("second-customer")
    own = add_task(console.app, user_id=first["id"])
    another_owned = add_task(console.app, user_id=first["id"])
    other = add_task(console.app, user_id=second["id"])
    own_url = f"/api/tasks/{own['id']}/ssh-host-key"
    another_url = f"/api/tasks/{another_owned['id']}/ssh-host-key"
    other_url = f"/api/tasks/{other['id']}/ssh-host-key"
    headers = login(console.client, "customer")
    response = console.client.get(own_url)
    assert response.status_code == 200, response.text
    token = response.json()["confirmation_token"]
    before = console.path.read_bytes()
    assert console.client.get(other_url).status_code == 404
    assert console.client.post(other_url, json={"confirmation_token": token}, headers=headers).status_code == 404
    assert console.client.post(another_url, json={"confirmation_token": token}, headers=headers).status_code == 409
    second_headers = login(console.client, "second-customer")
    assert console.client.get(own_url).status_code == 404
    assert console.client.post(own_url, json={"confirmation_token": token}, headers=second_headers).status_code == 404
    assert console.client.post(other_url, json={"confirmation_token": token}, headers=second_headers).status_code == 409
    admin_headers = login(console.client)
    assert console.client.post(own_url, json={"confirmation_token": token}, headers=admin_headers).status_code == 409
    assert console.path.read_bytes() == before
    console.probe.assert_awaited_once()


def test_completed_rotation_warning_is_returned_and_audited_with_new_pin(host_key_console, monkeypatch):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    warning = "SSH 指纹已更新，但锁文件清理失败，请管理员检查后再重试任务。"
    replace = main_module.replace_host_key

    def replace_with_warning(*args, **kwargs):
        replace(*args, **kwargs)
        return warning

    monkeypatch.setattr(main_module, "replace_host_key", replace_with_warning)
    response = confirm(console, headers, token)
    assert response.status_code == 200, response.text
    assert warning in response.json()["message"]
    target = [line for line in console.path.read_text().splitlines() if line.startswith("[8.8.8.8]:2222 ")]
    assert target == ["[8.8.8.8]:2222 " + console.new_key.export_public_key("openssh").decode().strip()]
    audit = console.app.state.store.events(console.task["id"])[-1]["message"]
    assert warning in audit
    assert fingerprint(console.old_key) in audit and fingerprint(console.new_key) in audit


def test_unchanged_host_key_does_not_offer_rotation_token(host_key_console):
    console = host_key_console
    login(console.client)
    console.probe.return_value = console.old_key.export_public_key("openssh").decode().strip()
    before = console.path.read_bytes()
    details = preview(console)
    assert details["changed"] is False
    assert details["confirmation_token"] == ""
    assert console.path.read_bytes() == before


@pytest.mark.parametrize("status", ["queued", "running", "succeeded"])
def test_rotation_only_available_for_failed_or_interrupted_tasks(host_key_console, status):
    console = host_key_console
    headers = login(console.client)
    with console.app.state.store.connect() as db:
        db.execute("UPDATE tasks SET status=? WHERE id=?", (status, console.task["id"]))
    before = console.path.read_bytes()
    assert console.client.get(console.url).status_code == 409
    assert confirm(console, headers, "test-only-invalid-confirmation-token").status_code == 409
    console.probe.assert_not_awaited()
    assert console.path.read_bytes() == before


def test_interrupted_task_can_preview_rotation(host_key_console):
    console = host_key_console
    login(console.client)
    with console.app.state.store.connect() as db:
        db.execute("UPDATE tasks SET status='interrupted' WHERE id=?", (console.task["id"],))
    assert preview(console)["changed"] is True


def test_active_task_on_same_ip_blocks_rotation_even_on_another_port(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    add_task(console.app, host="8.8.8.8", port=22, status="queued")
    before = console.path.read_bytes()
    assert console.client.get(console.url).status_code == 409
    assert confirm(console, headers, token).status_code == 409
    assert console.probe.await_count == 1
    assert console.path.read_bytes() == before


def test_active_task_on_another_ip_does_not_block_rotation(host_key_console):
    console = host_key_console
    headers = login(console.client)
    add_task(console.app, host="1.1.1.1", status="queued")
    token = preview(console)["confirmation_token"]
    assert confirm(console, headers, token).status_code == 200


def test_task_queued_during_confirmation_probe_blocks_update_and_audit(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]

    async def probe_while_new_task_is_queued(*args):
        add_task(console.app, host="8.8.8.8", port=22, status="queued")
        return console.new_key.export_public_key("openssh").decode().strip()

    console.probe.side_effect = probe_while_new_task_is_queued
    before = console.path.read_bytes()
    event_count = len(console.app.state.store.events(console.task["id"]))
    assert confirm(console, headers, token).status_code == 409
    assert console.path.read_bytes() == before
    assert len(console.app.state.store.events(console.task["id"])) == event_count


def test_discovery_failure_cannot_change_pins(host_key_console):
    console = host_key_console
    headers = login(console.client)
    before = console.path.read_bytes()
    token = preview(console)["confirmation_token"]
    console.probe.side_effect = remote.RemoteJobError("无法安全读取服务器 SSH 指纹。")
    assert console.client.get(console.url).status_code == 409
    assert confirm(console, headers, token).status_code == 409
    assert console.path.read_bytes() == before


def test_unpinned_target_has_no_rotation_token(host_key_console):
    console = host_key_console
    login(console.client)
    lines = [line for line in console.path.read_text().splitlines() if not line.startswith("[8.8.8.8]:2222 ")]
    console.path.write_text("\n".join(lines) + "\n")
    details = preview(console)
    assert details["stored_fingerprints"] == []
    assert details["changed"] is False
    assert details["confirmation_token"] == ""


def test_confirmation_must_reprobe_the_same_observed_key(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    console.probe.return_value = console.next_key.export_public_key("openssh").decode().strip()
    before = console.path.read_bytes()
    response = confirm(console, headers, token)
    assert response.status_code == 409
    assert console.probe.await_count == 2
    assert console.path.read_bytes() == before


def test_confirmation_cannot_overwrite_pin_changed_since_preview(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    public = console.next_key.export_public_key("openssh").decode().strip()
    lines = console.path.read_text().splitlines()
    console.path.write_text("\n".join("[8.8.8.8]:2222 " + public if line.startswith("[8.8.8.8]:2222 ") else line for line in lines) + "\n")
    before = console.path.read_bytes()
    assert confirm(console, headers, token).status_code == 409
    assert console.path.read_bytes() == before


def test_used_rotation_token_cannot_be_replayed(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    assert confirm(console, headers, token).status_code == 200
    before = console.path.read_bytes()
    count = len(console.app.state.store.events(console.task["id"]))
    assert confirm(console, headers, token).status_code == 409
    assert console.path.read_bytes() == before
    assert len(console.app.state.store.events(console.task["id"])) == count


def test_tampered_and_expired_tokens_cannot_rotate_pins(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    box = secret_box(console.app.state.settings.secret)
    plain = box.decrypt(token.encode())
    expired = box.encrypt_at_time(plain, int(time.time()) - 601).decode()
    tampered = token[:20] + ("A" if token[20] != "A" else "B") + token[21:]
    before = console.path.read_bytes()
    for invalid in ("not-a-signed-token", tampered, expired):
        assert confirm(console, headers, invalid).status_code == 409
        assert console.path.read_bytes() == before


def test_confirmation_token_is_bound_to_administrator_and_task(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    other = add_task(console.app)
    other_url = f"/api/tasks/{other['id']}/ssh-host-key"
    before = console.path.read_bytes()
    assert console.client.post(other_url, json={"confirmation_token": token}, headers=headers).status_code == 409
    second_headers = login(console.client, "second-admin")
    assert confirm(console, second_headers, token).status_code == 409
    assert console.path.read_bytes() == before


@pytest.mark.parametrize("field,replacement", [
    ("purpose", "different-action"),
    ("host", "1.1.1.1"),
    ("port", 22),
])
def test_signed_confirmation_is_bound_to_action_and_endpoint(host_key_console, field, replacement):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    box = secret_box(console.app.state.settings.secret)
    payload = json.loads(box.decrypt(token.encode()))
    payload[field] = replacement
    invalid = box.encrypt(json.dumps(payload).encode()).decode()
    before = console.path.read_bytes()
    assert confirm(console, headers, invalid).status_code == 409
    assert console.path.read_bytes() == before


def test_task_target_change_invalidates_previous_confirmation(host_key_console):
    console = host_key_console
    headers = login(console.client)
    token = preview(console)["confirmation_token"]
    with console.app.state.store.connect() as db:
        db.execute("UPDATE tasks SET ssh_port=22 WHERE id=?", (console.task["id"],))
    before = console.path.read_bytes()
    assert confirm(console, headers, token).status_code == 409
    assert console.path.read_bytes() == before

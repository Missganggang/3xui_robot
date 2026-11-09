import asyncio
import json
import sqlite3
import time
from unittest.mock import AsyncMock

import asyncssh
import pytest

from app import remote


class Connection:
    def __init__(self):
        self.closed = False
        self.aborted = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def abort(self):
        self.closed, self.aborted = True, True

    def is_closed(self):
        return self.closed


def job(kind="migrate"):
    return dict(id="reboot_test", kind=kind, server_ip="8.8.8.8", ssh_port=22,
                ssh_username="root", domain="panel.example.com", version="v2.9.4",
                source_version="2.9.4", panel_port=19000, panel_path="/temporary_path/",
                overwrite_existing=True, reset_two_factor=False,
                validation={"inbounds": 0, "clients": 0,
                            "panel_settings": {"port": 8443, "path": "/original/"}})


def wire_migration(tmp_path, monkeypatch, schedule_error=None, final_emit_error=False):
    connection = Connection()
    path = tmp_path / "upload.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password TEXT);
        INSERT INTO users VALUES(1,'original-admin','original-password-hash');
        CREATE TABLE settings(key TEXT,value TEXT);
        INSERT INTO settings VALUES('webPort','8443');
        INSERT INTO settings VALUES('webBasePath','/original/');
        CREATE TABLE inbounds(port INTEGER);
    """)
    db.commit(); db.close()
    steps, commands, events = [], [], []
    scheduled = False
    async def connect(*args):
        steps.append("connect")
        return connection
    async def run(conn, command, *args, **kwargs):
        nonlocal scheduled
        assert not scheduled, "No remote commands are allowed after reboot scheduling"
        commands.append(command)
        if command.startswith("systemd-run "):
            steps.append("reboot")
            scheduled = True
            assert "--on-active=5s /sbin/reboot" in command
            assert "boot_id" not in command
            if schedule_error is not None:
                raise schedule_error
            return ""
        steps.append("remote-command")
        return json.dumps({"existing": True}) if command == remote._python(remote._PREFLIGHT) else ""
    def record(name, result=None):
        async def call(*args, **kwargs):
            assert not scheduled, f"No {name} call is allowed after reboot scheduling"
            steps.append(name)
            return result
        return call
    async def emit(stage, message):
        events.append((stage, message))
        if final_emit_error and stage == "reboot" and scheduled:
            raise OSError("simulated final event failure")
    monkeypatch.setattr(remote, "_connect", AsyncMock(side_effect=connect))
    monkeypatch.setattr(remote, "_run", AsyncMock(side_effect=run))
    for name in ("_check_dns", "_probe_port", "_install", "_configure", "_configure_restored", "_verify_temporary_installation"):
        monkeypatch.setattr(remote, name, AsyncMock(side_effect=record(name)))
    monkeypatch.setattr(remote, "backup_remote", AsyncMock(side_effect=record("backup", "/var/backups/3xui-web/reboot_test")))
    monkeypatch.setattr(remote, "import_remote_database", AsyncMock(side_effect=record("import", {"inbounds": 0, "warnings": []})))
    monkeypatch.setattr(remote, "_verify_migration_counts", AsyncMock(side_effect=record("counts", {"inbounds": 0, "clients": 0})))
    monkeypatch.setattr(remote, "_issue_certificate", AsyncMock(side_effect=record("certificate", {"status": "valid"})))
    monkeypatch.setattr(remote, "_verify_preserved_migration_state", AsyncMock(side_effect=record("preserved")))
    monkeypatch.setattr(remote, "_enable_bbr", AsyncMock(side_effect=record("bbr", {"control": "cubic"})))
    monkeypatch.setattr(remote, "_wait_for_panel", AsyncMock(side_effect=record("https")))
    monkeypatch.setattr(remote, "_finalize_acme", AsyncMock(side_effect=record("cleanup")))
    monkeypatch.setattr(remote, "_verify_bbr", AsyncMock(side_effect=record("bbr-recheck")))
    monkeypatch.setattr(remote, "rollback_remote", AsyncMock(side_effect=record("rollback")))
    monkeypatch.setattr(remote, "_remove_acme_job", AsyncMock(side_effect=record("remove-acme")))
    monkeypatch.setattr(remote, "_restore_bbr", AsyncMock(side_effect=record("restore-bbr")))
    return path, connection, steps, commands, events, emit


def test_successful_migration_schedules_reboot_as_last_command_and_returns_original_address(tmp_path, monkeypatch):
    upload, connection, steps, commands, events, emit = wire_migration(tmp_path, monkeypatch)
    result = asyncio.run(remote.run_remote_job(job(), "private-ssh-password", upload, emit,
                                               remote.RemoteOptions(known_hosts_path=tmp_path / "known_hosts")))
    assert result["url"] == "https://panel.example.com:8443/original/"
    assert result["reboot_scheduled"] is True and result["reboot_verified"] is False
    assert result["credentials_preserved"] and result["panel_access_verified"]
    assert result["login_verified"] is False
    assert "username" not in result and "password" not in result
    assert steps[-1] == "reboot"
    assert steps.index("https") < steps.index("cleanup") < steps.index("reboot")
    assert commands[-1].startswith("systemd-run ")
    assert all("boot_id" not in command for command in commands)
    remote._connect.assert_awaited_once()
    remote._wait_for_panel.assert_awaited_once()
    remote._verify_migration_counts.assert_awaited_once()
    remote._verify_preserved_migration_state.assert_awaited_once()
    remote._verify_bbr.assert_not_awaited()
    remote.rollback_remote.assert_not_awaited()
    assert connection.closed
    assert all("private-ssh-password" not in message for _, message in events)


@pytest.mark.parametrize("error", [
    remote.RemoteJobError("服务器重启调度未得到确认。"),
    asyncssh.ConnectionLost("unconfirmed disconnect private/raw/detail"),
    asyncio.TimeoutError(),
])
def test_unconfirmed_reboot_preserves_successful_migration_without_reconnect_or_rollback(tmp_path, monkeypatch, error):
    upload, connection, steps, commands, events, emit = wire_migration(tmp_path, monkeypatch, schedule_error=error)
    result = asyncio.run(remote.run_remote_job(job(), "private-ssh-password", upload, emit,
                                               remote.RemoteOptions(known_hosts_path=tmp_path / "known_hosts")))
    assert result["reboot_scheduled"] is False and result["reboot_verified"] is False
    assert result["panel_access_verified"] and result["credentials_preserved"]
    assert any("手动重启" in warning and "未得到确认" in warning for warning in result["warnings"])
    assert "private/raw/detail" not in str(result)
    assert result["url"] == "https://panel.example.com:8443/original/"
    assert steps[-1] == "reboot"
    remote._connect.assert_awaited_once()
    remote.rollback_remote.assert_not_awaited()
    remote._remove_acme_job.assert_not_awaited()
    remote._restore_bbr.assert_not_awaited()


@pytest.mark.parametrize("schedule_error", [None, remote.RemoteJobError("unconfirmed")])
def test_progress_failure_after_schedule_cannot_trigger_rollback(tmp_path, monkeypatch, schedule_error):
    upload, connection, steps, commands, events, emit = wire_migration(
        tmp_path, monkeypatch, schedule_error=schedule_error, final_emit_error=True)
    result = asyncio.run(remote.run_remote_job(job(), "private-ssh-password", upload, emit,
                                               remote.RemoteOptions(known_hosts_path=tmp_path / "known_hosts")))
    assert result["reboot_scheduled"] is (schedule_error is None)
    assert any("日志未能保存" in warning for warning in result["warnings"])
    remote._connect.assert_awaited_once()
    remote.rollback_remote.assert_not_awaited()
    assert steps[-1] == "reboot"


def test_business_failure_before_reboot_still_restores_snapshot(tmp_path, monkeypatch):
    upload, connection, steps, commands, events, emit = wire_migration(tmp_path, monkeypatch)
    remote._wait_for_panel.side_effect = remote.RemoteJobError("迁移后 HTTPS 检查失败。")
    with pytest.raises(remote.RemoteJobError, match="HTTPS 检查失败"):
        asyncio.run(remote.run_remote_job(job(), "private-ssh-password", upload, emit,
                                         remote.RemoteOptions(known_hosts_path=tmp_path / "known_hosts")))
    assert "reboot" not in steps
    remote.rollback_remote.assert_awaited_once()
    remote._remove_acme_job.assert_awaited_once()
    remote._restore_bbr.assert_awaited_once()


def test_new_install_does_not_schedule_server_reboot(tmp_path, monkeypatch):
    upload, connection, steps, commands, events, emit = wire_migration(tmp_path, monkeypatch)
    result = asyncio.run(remote.run_remote_job(job(kind="install"), "private-ssh-password", None, emit,
                                               remote.RemoteOptions(known_hosts_path=tmp_path / "known_hosts")))
    assert result["username"] == "qqqzzz" and result["password"] == "qqqzzz"
    assert result["login_verified"] is True
    assert "reboot_scheduled" not in result
    assert "reboot" not in steps
    remote._connect.assert_awaited_once()
    remote._wait_for_panel.assert_awaited_once()


@pytest.mark.parametrize("kind", ["disconnect", "hang"])
def test_final_connection_close_is_bounded_and_does_not_raise(kind):
    connection = Connection()
    if kind == "disconnect":
        async def wait_closed():
            raise asyncssh.ConnectionLost("expected reboot EOF")
    else:
        async def wait_closed():
            await asyncio.Event().wait()
    connection.wait_closed = wait_closed
    async def run():
        start = time.monotonic()
        await remote._close_connection(connection, start + 0.02)
        assert time.monotonic() - start < 0.2
        assert connection.aborted
    asyncio.run(run())

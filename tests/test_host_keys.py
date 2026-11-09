import asyncio
import os
from pathlib import Path
import stat
from unittest.mock import AsyncMock

import asyncssh
import pytest

from app import host_keys
from app.remote import RemoteJobError, _record_host_key


def key():
    return asyncssh.generate_private_key("ssh-ed25519")


def public(value):
    return value.export_public_key("openssh").decode("ascii").strip()


def test_missing_pin_file_returns_empty_without_creating_files(tmp_path):
    path = tmp_path / "missing" / "known_hosts"
    assert host_keys.read_host_keys(path, "8.8.8.8", 22) == []
    assert not path.parent.exists()


def test_key_summary_normalizes_comments_and_whitespace():
    original = key()
    serialized = public(original)
    summary = host_keys.key_summary("  " + serialized + " imported comment\n")
    assert summary == {"algorithm": "ssh-ed25519", "fingerprint": original.get_fingerprint("sha256")}
    with pytest.raises(RemoteJobError):
        host_keys.key_summary(serialized + "\n" + serialized)


def test_reads_pins_written_by_existing_remote_lock_and_format(tmp_path):
    path = tmp_path / "known_hosts"
    original = key()
    assert _record_host_key(path, "8.8.8.8", 22, original)
    assert host_keys.read_host_keys(path, "8.8.8.8", 22) == [public(original)]
    assert not path.with_name("known_hosts.lock").exists()


@pytest.mark.parametrize("line", [
    "[8.8.8.8]:22", "[8.8.8.8]:22 ssh-ed25519 invalid-base64",
    " [8.8.8.8]:22 {key}", "[8.8.8.8]:22\t{key}",
    "@revoked [8.8.8.8]:22 {key}", "[8.8.8.8]:22,[1.1.1.1]:22 {key}",
    "[8.8.8.8]:22ssh-ed25519 invalid-base64",
])
def test_malformed_same_scope_records_fail_closed(tmp_path, line):
    path = tmp_path / "known_hosts"
    path.write_text(line.format(key=public(key())) + "\n", encoding="ascii")
    before = path.read_bytes()
    with pytest.raises(RemoteJobError):
        host_keys.read_host_keys(path, "8.8.8.8", 22)
    assert path.read_bytes() == before


def test_duplicate_and_multiple_distinct_pins_fail_closed_like_existing_worker(tmp_path):
    path = tmp_path / "known_hosts"
    first, second = public(key()), public(key())
    path.write_text(f"[8.8.8.8]:22 {first}\n[8.8.8.8]:22 {first} another-comment\n", encoding="ascii")
    with pytest.raises(RemoteJobError, match="重复"):
        host_keys.read_host_keys(path, "8.8.8.8", 22)
    path.write_text(f"[8.8.8.8]:22 {first}\n[8.8.8.8]:22 {second}\n", encoding="ascii")
    with pytest.raises(RemoteJobError, match="多条"):
        host_keys.read_host_keys(path, "8.8.8.8", 22)


def test_replace_is_compatible_with_record_and_preserves_other_scopes_exactly(tmp_path):
    path = tmp_path / "known_hosts"
    old_key, new_key = key(), key()
    prefix = b"# administrator comment\r\n[1.1.1.1]:22 unrelated-malformed-key-kept\r\n"
    suffix = b"[8.8.8.8]:2222 unrelated-other-port-no-newline"
    path.write_bytes(prefix + f"[8.8.8.8]:22 {public(old_key)} old-comment\r\n".encode("ascii") + suffix)
    expected = host_keys.read_host_keys(path, "8.8.8.8", 22)
    host_keys.replace_host_key(path, "8.8.8.8", 22, expected, public(new_key) + " new-comment\n")
    assert path.read_bytes() == prefix + f"[8.8.8.8]:22 {public(new_key)}\r\n".encode("ascii") + suffix
    assert _record_host_key(path, "8.8.8.8", 22, new_key)
    assert not _record_host_key(path, "8.8.8.8", 22, old_key)
    assert not path.with_name("known_hosts.lock").exists()


def test_compare_and_swap_refuses_changed_scope_and_confirmation_replay(tmp_path):
    path = tmp_path / "known_hosts"
    first, second, stale = public(key()), public(key()), public(key())
    path.write_text(f"[8.8.8.8]:22 {first}\n", encoding="ascii")
    before = path.read_bytes()
    with pytest.raises(RemoteJobError, match="已变化"):
        host_keys.replace_host_key(path, "8.8.8.8", 22, [stale], second)
    assert path.read_bytes() == before
    host_keys.replace_host_key(path, "8.8.8.8", 22, [first], second)
    changed = path.read_bytes()
    with pytest.raises(RemoteJobError, match="已变化"):
        host_keys.replace_host_key(path, "8.8.8.8", 22, [first], second)
    with pytest.raises(RemoteJobError, match="重复确认"):
        host_keys.replace_host_key(path, "8.8.8.8", 22, [second], second)
    assert path.read_bytes() == changed


def test_replace_requires_an_existing_scope_and_nonempty_expected_list(tmp_path):
    path = tmp_path / "known_hosts"
    existing, replacement = public(key()), public(key())
    path.write_text(f"[1.1.1.1]:22 {existing}\n", encoding="ascii")
    before = path.read_bytes()
    for expected in ([], [existing]):
        with pytest.raises(RemoteJobError):
            host_keys.replace_host_key(path, "8.8.8.8", 22, expected, replacement)
    assert path.read_bytes() == before


def test_atomic_replace_failure_keeps_old_file_and_removes_temporary_files(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    old, new = public(key()), public(key())
    path.write_text(f"[8.8.8.8]:22 {old}\n", encoding="ascii")
    before = path.read_bytes()
    def fail_replace(*args):
        raise OSError("simulated filesystem failure")
    monkeypatch.setattr(host_keys.os, "replace", fail_replace)
    with pytest.raises(RemoteJobError, match="更新失败"):
        host_keys.replace_host_key(path, "8.8.8.8", 22, [old], new)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_committed_replace_returns_warning_if_lock_release_fails(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    old, new = public(key()), public(key())
    path.write_text(f"[8.8.8.8]:22 {old}\n", encoding="ascii")
    lock = path.with_name("known_hosts.lock")
    original_unlink = Path.unlink
    def blocked_unlink(target, *args, **kwargs):
        if target == lock:
            raise OSError("simulated lock cleanup failure")
        return original_unlink(target, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", blocked_unlink)
    warning = host_keys.replace_host_key(path, "8.8.8.8", 22, [old], new)
    assert "指纹已更新" in warning and "锁未释放" in warning
    assert path.read_text("ascii") == f"[8.8.8.8]:22 {new}\n"
    assert lock.exists()
    with pytest.raises(RemoteJobError, match="正忙"):
        host_keys.read_host_keys(path, "8.8.8.8", 22)
    original_unlink(lock)


@pytest.mark.parametrize("operation", ["read", "uncommitted_replace"])
def test_uncommitted_lock_release_failure_remains_an_error(tmp_path, monkeypatch, operation):
    path = tmp_path / "known_hosts"
    old, new, stale = public(key()), public(key()), public(key())
    path.write_text(f"[8.8.8.8]:22 {old}\n", encoding="ascii")
    before = path.read_bytes()
    lock = path.with_name("known_hosts.lock")
    original_unlink = Path.unlink
    def blocked_unlink(target, *args, **kwargs):
        if target == lock:
            raise OSError("simulated lock cleanup failure")
        return original_unlink(target, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", blocked_unlink)
    with pytest.raises(RemoteJobError, match="锁文件无法释放"):
        if operation == "read":
            host_keys.read_host_keys(path, "8.8.8.8", 22)
        else:
            host_keys.replace_host_key(path, "8.8.8.8", 22, [stale], new)
    assert path.read_bytes() == before
    original_unlink(lock)


def test_lock_is_shared_with_remote_record_and_never_deleted_by_nonowner(tmp_path):
    path = tmp_path / "known_hosts"
    old, new = key(), key()
    assert _record_host_key(path, "8.8.8.8", 22, old)
    lock = path.with_name("known_hosts.lock")
    lock.write_bytes(b"owned by another operation")
    for operation in (
        lambda: host_keys.read_host_keys(path, "8.8.8.8", 22),
        lambda: host_keys.replace_host_key(path, "8.8.8.8", 22, [public(old)], public(new)),
        lambda: host_keys.remember_host_key(path, "8.8.8.8", 22, new),
        lambda: _record_host_key(path, "8.8.8.8", 22, new),
    ):
        with pytest.raises(RemoteJobError, match="正忙"):
            operation()
    assert lock.read_bytes() == b"owned by another operation"


def test_automatic_remember_records_first_handshake_key_atomically_with_private_permissions(tmp_path, monkeypatch):
    path = tmp_path / "private" / "known_hosts"
    handshake_key = key()
    real_replace = os.replace
    observed = []
    def inspect_replace(source, target):
        assert target == path and not path.exists()
        assert source.parent == path.parent
        assert source.read_bytes() == f"[8.8.8.8]:22 {public(handshake_key)}\n".encode("ascii")
        if os.name != "nt":
            assert stat.S_IMODE(source.stat().st_mode) == 0o600
        observed.append(source)
        return real_replace(source, target)
    monkeypatch.setattr(host_keys.os, "replace", inspect_replace)
    result = host_keys.remember_host_key(path, "8.8.8.8", 22, handshake_key)
    assert result == {"changed": False, "old_fingerprints": [],
                      "new_fingerprint": handshake_key.get_fingerprint("sha256"), "warning": None}
    assert len(observed) == 1
    assert list(path.parent.iterdir()) == [path]
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_automatic_remember_same_key_does_not_rewrite_existing_bytes(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    handshake_key = key()
    content = f"# original comment\r\n[8.8.8.8]:22 {public(handshake_key)} keep-this-comment\r\n".encode("ascii")
    path.write_bytes(content)
    def forbidden_replace(*args):
        pytest.fail("The same handshake key must not replace the file")
    monkeypatch.setattr(host_keys.os, "replace", forbidden_replace)
    result = host_keys.remember_host_key(path, "8.8.8.8", 22, handshake_key)
    assert result == {"changed": False, "old_fingerprints": [handshake_key.get_fingerprint("sha256")],
                      "new_fingerprint": handshake_key.get_fingerprint("sha256"), "warning": None}
    assert path.read_bytes() == content
    assert list(tmp_path.iterdir()) == [path]


def test_automatic_rotation_is_atomic_and_preserves_other_ip_ports_and_bytes(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    old, handshake_key = key(), key()
    prefix = b"# raw comment \xff\r\n[1.1.1.1]:22 malformed-other-ip-is-preserved\r\n"
    suffix = b"[8.8.8.8]:2222 malformed-other-port-without-newline"
    before = prefix + f"[8.8.8.8]:22 {public(old)} old-comment\r\n".encode("ascii") + suffix
    expected = prefix + f"[8.8.8.8]:22 {public(handshake_key)}\r\n".encode("ascii") + suffix
    path.write_bytes(before)
    real_replace = os.replace
    def inspect_replace(source, target):
        assert target == path
        assert path.read_bytes() == before
        assert source.read_bytes() == expected
        return real_replace(source, target)
    monkeypatch.setattr(host_keys.os, "replace", inspect_replace)
    result = host_keys.remember_host_key(path, "8.8.8.8", 22, handshake_key)
    assert result == {"changed": True, "old_fingerprints": [old.get_fingerprint("sha256")],
                      "new_fingerprint": handshake_key.get_fingerprint("sha256"), "warning": None}
    assert path.read_bytes() == expected
    assert list(tmp_path.iterdir()) == [path]


def test_automatic_remember_adds_new_scope_without_truncating_unterminated_line(tmp_path):
    path = tmp_path / "known_hosts"
    first, second = key(), key()
    prefix = f"[1.1.1.1]:2222 {public(first)} original-no-newline".encode("ascii")
    path.write_bytes(prefix)
    result = host_keys.remember_host_key(path, "8.8.8.8", 22, second)
    assert result["changed"] is False and result["old_fingerprints"] == []
    assert path.read_bytes() == prefix + f"\n[8.8.8.8]:22 {public(second)}\n".encode("ascii")


def test_automatic_rotation_uses_canonical_ipv6_scope_and_keeps_other_ports(tmp_path):
    path = tmp_path / "known_hosts"
    old, new = key(), key()
    suffix = b"[2001:4860:4860::8888]:2222 unrelated\n"
    path.write_bytes(f"[2001:4860:4860::8888]:22 {public(old)}\n".encode("ascii") + suffix)
    result = host_keys.remember_host_key(path, "2001:4860:4860:0:0:0:0:8888", 22, new)
    assert result["changed"] is True
    assert path.read_bytes() == f"[2001:4860:4860::8888]:22 {public(new)}\n".encode("ascii") + suffix


@pytest.mark.parametrize("operation", ["replace", "fsync", "chmod"])
@pytest.mark.parametrize("existing", [True, False])
def test_automatic_remember_filesystem_failure_does_not_cover_or_partially_write_pin(tmp_path, monkeypatch, operation, existing):
    path = tmp_path / "known_hosts"
    before = f"[8.8.8.8]:22 {public(key())}\n".encode("ascii")
    if existing:
        path.write_bytes(before)
    def fail(*args, **kwargs):
        raise OSError("private/filesystem/failure")
    monkeypatch.setattr(host_keys.os, operation, fail)
    with pytest.raises(RemoteJobError, match="保存失败") as error:
        host_keys.remember_host_key(path, "8.8.8.8", 22, key())
    assert "private/filesystem/failure" not in str(error.value)
    assert path.read_bytes() == before if existing else not path.exists()
    assert list(tmp_path.iterdir()) == ([path] if existing else [])


@pytest.mark.parametrize("record", [
    "[8.8.8.8]:22", "[8.8.8.8]:22 ssh-ed25519 invalid-base64",
    " [8.8.8.8]:22 {old}", "[8.8.8.8]:22\t{old}",
    "@revoked [8.8.8.8]:22 {old}", "[8.8.8.8]:22,[1.1.1.1]:22 {old}",
    "[8.8.8.8]:22 {old}\n[8.8.8.8]:22 {old}",
    "[8.8.8.8]:22 {old}\n[8.8.8.8]:22 {another}",
])
def test_automatic_remember_does_not_overwrite_damaged_or_ambiguous_scope(tmp_path, record):
    path = tmp_path / "known_hosts"
    before = (record.format(old=public(key()), another=public(key())) + "\n").encode("ascii")
    path.write_bytes(before)
    with pytest.raises(RemoteJobError):
        host_keys.remember_host_key(path, "8.8.8.8", 22, key())
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_automatic_remember_rejects_symlink_pin_file_without_writing_target(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    before = f"[8.8.8.8]:22 {public(key())}\n".encode("ascii")
    path.write_bytes(before)
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == path or real_is_symlink(self))
    with pytest.raises(RemoteJobError, match="文件异常"):
        host_keys.remember_host_key(path, "8.8.8.8", 22, key())
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_automatic_remember_returns_committed_warning_if_lock_cleanup_fails(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    old, new = key(), key()
    path.write_text(f"[8.8.8.8]:22 {public(old)}\n", encoding="ascii")
    lock = path.with_name("known_hosts.lock")
    real_unlink = Path.unlink
    def blocked_unlink(target, *args, **kwargs):
        if target == lock:
            raise PermissionError("private cleanup error")
        return real_unlink(target, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", blocked_unlink)
    result = host_keys.remember_host_key(path, "8.8.8.8", 22, new)
    assert result["changed"] is True
    assert "指纹已更新" in result["warning"] and "锁未释放" in result["warning"]
    assert path.read_text("ascii") == f"[8.8.8.8]:22 {public(new)}\n"
    assert lock.exists()
    real_unlink(lock)


def test_automatic_remember_refuses_to_grow_beyond_host_file_limit(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    before = b"# existing file\n"
    path.write_bytes(before)
    monkeypatch.setattr(host_keys, "MAX_HOSTS_FILE_BYTES", len(before) + 1)
    with pytest.raises(RemoteJobError, match="文件过大"):
        host_keys.remember_host_key(path, "8.8.8.8", 22, key())
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_automatic_remember_same_key_permission_failure_still_stops_safely(tmp_path, monkeypatch):
    path = tmp_path / "known_hosts"
    handshake_key = key()
    before = f"[8.8.8.8]:22 {public(handshake_key)}\n".encode("ascii")
    path.write_bytes(before)
    def blocked_permissions(*args, **kwargs):
        raise PermissionError("private file permissions")
    monkeypatch.setattr(host_keys.os, "chmod", blocked_permissions)
    with pytest.raises(RemoteJobError, match="保存失败"):
        host_keys.remember_host_key(path, "8.8.8.8", 22, handshake_key)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_automatic_remember_rejects_invalid_handshake_key_before_creating_pin_directory(tmp_path):
    path = tmp_path / "absent" / "known_hosts"
    with pytest.raises(RemoteJobError, match="公钥格式无效"):
        host_keys.remember_host_key(path, "8.8.8.8", 22, object())
    assert not path.parent.exists()


def test_probe_stops_before_user_authentication_on_local_ssh_server():
    auth_attempts = []
    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            auth_attempts.append(username)
            return True
    async def run():
        original = key()
        server = await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[original])
        try:
            candidate = await host_keys.probe_host_key("127.0.0.1", server.get_port())
            assert candidate == public(original)
            assert host_keys.key_summary(candidate)["fingerprint"] == original.get_fingerprint("sha256")
            assert auth_attempts == []
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(run())


def test_probe_timeout_is_bounded_and_uses_no_configuration_or_credentials(monkeypatch):
    cancelled = []
    async def hang(*args, **kwargs):
        assert args == ("8.8.8.8",)
        assert kwargs == {"port": 22, "config": None}
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)
    monkeypatch.setattr(host_keys.asyncssh, "get_server_host_key", hang)
    monkeypatch.setattr(host_keys, "PROBE_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(RemoteJobError, match="无法获取"):
        asyncio.run(host_keys.probe_host_key("8.8.8.8", 22))
    assert cancelled == [True]


def test_probe_failure_returns_safe_error_without_raw_server_details(monkeypatch):
    monkeypatch.setattr(host_keys.asyncssh, "get_server_host_key", AsyncMock(side_effect=OSError("private/raw/server/detail")))
    with pytest.raises(RemoteJobError) as error:
        asyncio.run(host_keys.probe_host_key("8.8.8.8", 22))
    assert "private/raw/server/detail" not in str(error.value)

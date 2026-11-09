"""Inspect and update application-owned SSH host key pins.

Probes finish after key exchange and never authenticate. Both manual replacement
and automatic handshake recording use the shared ``known_hosts.lock`` creation
lock and atomic file replacement. The manual API also compares the old scope.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import ipaddress
import os
from pathlib import Path
import re
import tempfile

import asyncssh

from .remote import RemoteJobError


PROBE_TIMEOUT_SECONDS = 20
MAX_HOSTS_FILE_BYTES = 4 * 1024 * 1024


def _target(host: str, port: int) -> tuple[str, int, str]:
    try:
        address = str(ipaddress.ip_address(host))
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise RemoteJobError("SSH 服务器 IP 或端口无效。") from exc
    return address, port, f"[{address}]:{port}"


def _normalize_key(public_key: str) -> str:
    if not isinstance(public_key, str):
        raise RemoteJobError("SSH 主机公钥格式无效。")
    value = public_key.strip()
    if not value or len(value) > 65536 or "\n" in value or "\r" in value:
        raise RemoteJobError("SSH 主机公钥格式无效。")
    try:
        key = asyncssh.import_public_key(value)
        # Comments do not identify a key. Strip them so an old formatting or
        # comment change cannot defeat scope comparison or confirmation replay.
        key.set_comment(None)
        return key.export_public_key("openssh").decode("ascii").strip()
    except (ValueError, TypeError, UnicodeError) as exc:
        raise RemoteJobError("SSH 主机公钥格式无效。") from exc


def key_summary(public_key: str) -> dict:
    key = asyncssh.import_public_key(_normalize_key(public_key))
    return {"algorithm": key.get_algorithm(), "fingerprint": key.get_fingerprint("sha256")}


@contextmanager
def _host_file_lock(path: Path):
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RemoteJobError("SSH 指纹库正忙，请稍后重试。") from exc
    except OSError as exc:
        raise RemoteJobError("无法安全锁定 SSH 指纹库，请管理员检查权限。") from exc
    state = {"committed": False, "warning": None}
    try:
        os.close(descriptor)
        yield state
    finally:
        try:
            lock.unlink(missing_ok=True)
        except OSError as exc:
            if state["committed"]:
                state["warning"] = "SSH 指纹已更新，但指纹库锁未释放；请管理员检查并清理指纹库锁文件后重试连接。"
            else:
                raise RemoteJobError("SSH 指纹库锁文件无法释放，请管理员检查。") from exc


def _read_file(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_HOSTS_FILE_BYTES:
            raise RemoteJobError("SSH 指纹库文件异常，请管理员检查。")
        return path.read_bytes()
    except OSError as exc:
        raise RemoteJobError("无法读取 SSH 指纹库，请管理员检查权限。") from exc


def _scope_lines(contents: bytes, identity: str) -> tuple[list[bytes], list[int], list[str]]:
    lines = contents.splitlines(keepends=True)
    indices, keys = [], []
    for index, raw in enumerate(lines):
        line = raw.decode("utf-8", errors="surrogateescape").rstrip("\r\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        names = fields[1] if fields[0].startswith("@") and len(fields) > 1 else fields[0]
        belongs = identity in names.split(",")
        # A key line with a missing separator after this scope is malformed.
        # A different port such as :2222 remains a separate scope from :22.
        malformed_prefix = re.match(re.escape(identity) + r"(?![0-9])", names) is not None
        if not belongs and not malformed_prefix:
            continue
        if names != identity or fields[0] != identity or not line.startswith(identity + " ") or len(fields) < 3:
            raise RemoteJobError("该服务器的 SSH 指纹记录格式异常，已停止自动确认，请管理员检查。")
        key = _normalize_key(stripped.split(None, 1)[1])
        if key in keys:
            raise RemoteJobError("该服务器存在重复 SSH 指纹记录，已停止自动确认，请管理员检查。")
        if keys:
            raise RemoteJobError("该服务器存在多条 SSH 指纹记录，当前执行器无法使用，请管理员检查。")
        indices.append(index)
        keys.append(key)
    return lines, indices, keys


def read_host_keys(path: Path, host: str, port: int) -> list[str]:
    """Return normalized pins for one literal-IP scope, failing on bad lines."""
    _, _, identity = _target(host, port)
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return []
    with _host_file_lock(path):
        _, _, keys = _scope_lines(_read_file(path), identity)
        return keys


async def probe_host_key(host: str, port: int) -> str:
    """Retrieve a candidate key without credentials, user authentication or commands.

    The caller must apply its public/private target policy before invoking this
    helper. An unauthenticated probe is evidence to compare with a trusted
    console fingerprint; it does not establish ownership of a replacement key.
    """
    address, port, _ = _target(host, port)
    try:
        key = await asyncio.wait_for(
            asyncssh.get_server_host_key(address, port=port, config=None),
            timeout=PROBE_TIMEOUT_SECONDS,
        )
        if key is None:
            raise RemoteJobError("服务器没有提供可用的 SSH 主机公钥，无法确认指纹。")
        return _normalize_key(key.export_public_key("openssh").decode("ascii"))
    except RemoteJobError:
        raise
    except (asyncssh.Error, OSError, asyncio.TimeoutError, ValueError, UnicodeError) as exc:
        raise RemoteJobError("无法获取服务器 SSH 指纹，请检查 IP、端口和 SSH 服务后重试。") from exc


def replace_host_key(path: Path, host: str, port: int, expected_keys: list[str], new_key: str) -> str | None:
    """Atomically replace an existing scope only if its old pins still match."""
    _, _, identity = _target(host, port)
    if not isinstance(expected_keys, list) or not expected_keys:
        raise RemoteJobError("没有可核对的旧 SSH 指纹记录，不能使用变更确认。")
    expected = [_normalize_key(key) for key in expected_keys]
    if len(expected) != len(set(expected)):
        raise RemoteJobError("待确认的旧 SSH 指纹记录重复，请重新获取确认信息。")
    new_key = _normalize_key(new_key)
    path = Path(path)
    temporary: Path | None = None
    with _host_file_lock(path) as lock_state:
        try:
            lines, indices, current = _scope_lines(_read_file(path), identity)
            if not current or set(current) != set(expected):
                raise RemoteJobError("SSH 指纹记录已变化，请重新检查并发起确认。")
            if new_key in current:
                raise RemoteJobError("该 SSH 指纹已保存，无需重复确认。")
            newline = b"\r\n" if lines[indices[0]].endswith(b"\r\n") else b"\n"
            replacement = identity.encode("ascii") + b" " + new_key.encode("ascii") + newline
            selected = set(indices)
            output = b"".join(replacement if index == indices[0] else b"" if index in selected else line
                              for index, line in enumerate(lines))
            with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as target:
                temporary = Path(target.name)
                os.chmod(temporary, 0o600)
                target.write(output)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            lock_state["committed"] = True
            temporary = None
        except OSError as exc:
            raise RemoteJobError("SSH 指纹更新失败，原记录未被直接覆盖，请管理员检查文件权限。") from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
    return lock_state["warning"]


def remember_host_key(path: Path, host: str, port: int, key: asyncssh.SSHKey) -> dict:
    """Record the actual handshake key under the authorized automatic policy.

    An existing different key is replaced for this one literal IP and port.
    The handshake caller must still require successful recording before trusting
    the key. This synchronous operation does not open another SSH connection.
    """
    _, _, identity = _target(host, port)
    try:
        public_key = _normalize_key(key.export_public_key("openssh").decode("ascii"))
    except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
        raise RemoteJobError("SSH 主机公钥格式无效，无法保存当前握手指纹。") from exc
    new_fingerprint = key_summary(public_key)["fingerprint"]
    path = Path(path)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise RemoteJobError("无法创建 SSH 指纹库目录，请管理员检查权限。") from exc
    temporary: Path | None = None
    with _host_file_lock(path) as lock_state:
        try:
            contents = _read_file(path) if path.exists() or path.is_symlink() else b""
            lines, indices, current = _scope_lines(contents, identity)
            old_fingerprints = [key_summary(value)["fingerprint"] for value in current]
            changed = bool(current and current != [public_key])
            if current == [public_key]:
                # Preserve comments, line endings and all bytes for an unchanged
                # key while enforcing the same permission as newly written pins.
                os.chmod(path, 0o600)
            else:
                if indices:
                    newline = b"\r\n" if lines[indices[0]].endswith(b"\r\n") else b"\n"
                    replacement = identity.encode("ascii") + b" " + public_key.encode("ascii") + newline
                    output = b"".join(replacement if index == indices[0] else line
                                      for index, line in enumerate(lines))
                else:
                    newline = b"\r\n" if b"\r\n" in contents else b"\n"
                    separator = b"\n" if contents and not contents.endswith(b"\n") else b""
                    output = contents + separator + identity.encode("ascii") + b" " + public_key.encode("ascii") + newline
                if len(output) > MAX_HOSTS_FILE_BYTES:
                    raise RemoteJobError("SSH 指纹库文件过大，无法安全保存当前握手指纹。")
                with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as target:
                    temporary = Path(target.name)
                    os.chmod(temporary, 0o600)
                    target.write(output)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(temporary, path)
                lock_state["committed"] = True
                temporary = None
        except OSError as exc:
            raise RemoteJobError("SSH 指纹保存失败，原记录未被直接覆盖，请管理员检查文件权限。") from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
    return {"changed": changed, "old_fingerprints": old_fingerprints,
            "new_fingerprint": new_fingerprint, "warning": lock_state["warning"]}

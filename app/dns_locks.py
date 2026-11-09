"""Serialize a zone's writes across requests and local server processes."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import errno
import hashlib
import os
from pathlib import Path
import time

from .cloudflare import CloudflareError


@asynccontextmanager
async def zone_write_lock(data_dir: Path, account_id: str, zone_id: str, timeout: float = 10):
    # Locks are held by the OS, so a stopped process cannot leave a stale lock.
    name = hashlib.sha256((account_id + ":" + zone_id).encode()).hexdigest() + ".lock"
    descriptor = None
    locked = False
    try:
        folder = data_dir / "dns-locks"
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        descriptor = os.open(folder / name, os.O_CREAT | os.O_RDWR, 0o600)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"0")
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise
                if time.monotonic() >= deadline:
                    raise CloudflareError("该域名正在处理其他 DNS 操作，请稍后重试。", 409) from None
                await asyncio.sleep(0.05)
        yield
    except OSError:
        raise CloudflareError("无法锁定域名的 DNS 写入，请管理员检查数据目录权限。", 503) from None
    finally:
        if descriptor is not None:
            try:
                if locked:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

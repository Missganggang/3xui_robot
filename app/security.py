from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import time
from collections import defaultdict, deque

from cryptography.fernet import Fernet


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 256:
        raise ValueError("网站登录密码须为 12–256 个字符。")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt, digest = encoded.split("$")
        if algorithm != "scrypt" or len(password) > 256:
            return False
        result = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(result, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def secret_box(secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("job-secret:" + secret).encode()).digest()))


def validate_username(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", value):
        raise ValueError("网站用户名须为 3–64 位字母、数字或 _.@-。")
    return value


def validate_target(value: str, allow_private: bool = False) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("请输入服务器 IP 地址，不能填写网址或主机名。") from None
    if not allow_private and not address.is_global:
        raise ValueError("只允许公网服务器 IP，不能连接本机、内网或云元数据地址。")
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError("不支持此服务器 IP 地址。")
    return str(address)


def validate_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if any(x in value for x in ("/", ":", "*", "@", " ", "\n", "\r")):
        raise ValueError("只填写域名，例如 panel.example.com，不含 https://、端口或路径。")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("域名格式错误。") from None
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("请输入有效的完整域名，例如 panel.example.com。")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("证书绑定需要域名，不能填写 IP。")


class LoginLimiter:
    """Per-process limiter; production edge should also rate-limit login."""

    def __init__(self) -> None:
        self.attempts: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        if len(self.attempts) > 10000:
            self.attempts = defaultdict(deque, {k: v for k, v in self.attempts.items() if v and v[-1] > now - 900})
        bucket = self.attempts[key]
        while bucket and bucket[0] < now - 900:
            bucket.popleft()
        if len(bucket) >= 10:
            return False
        bucket.append(now)
        return True

    def success(self, key: str) -> None:
        bucket = self.attempts.get(key)
        if bucket:
            bucket.pop()

"""Bounded Cloudflare DNS calls and account-scoped record validation."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

import httpx
import idna
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


class CloudflareError(RuntimeError):
    """A customer-safe message, without an upstream response or credentials."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


_ID = re.compile(r"[0-9a-fA-F]{32}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_RECORD_FIELDS = ("id", "type", "name", "content", "ttl", "proxied", "priority", "comment")


def validate_id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise CloudflareError("Cloudflare 资源编号无效。", 422)
    return value.lower()


class DnsRecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["A", "AAAA", "CNAME", "TXT", "MX"]
    name: str = Field(min_length=1, max_length=253, strict=True)
    content: str = Field(min_length=1, max_length=4096, strict=True)
    ttl: int = Field(default=1, strict=True)
    proxied: StrictBool = False
    priority: int | None = Field(default=None, ge=0, le=65535, strict=True)
    comment: str | None = Field(default=None, max_length=500, strict=True)

    @field_validator("ttl")
    @classmethod
    def supported_ttl(cls, value: int) -> int:
        if value != 1 and not 60 <= value <= 86400:
            raise ValueError("TTL 必须为 1（自动）或 60–86400 秒。")
        return value


def _domain(value: str, *, wildcard: bool = False, underscore_labels: bool = False) -> str:
    if not isinstance(value, str):
        raise CloudflareError("DNS 名称无效，请填写域名。", 422)
    # Accept the equivalent Unicode dot characters before checking labels.
    value = value.strip().translate(str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."}))
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253:
        raise CloudflareError("DNS 名称无效或超过 253 个字符。", 422)
    labels = []
    for index, label in enumerate(value.split(".")):
        if label == "*" and wildcard and index == 0:
            labels.append(label)
            continue
        prefix = ""
        if underscore_labels:
            prefix = label[: len(label) - len(label.lstrip("_"))]
            label = label[len(prefix):]
        try:
            encoded = idna.encode(label, uts46=True, std3_rules=True).decode("ascii").lower()
        except (idna.IDNAError, UnicodeError) as exc:
            raise CloudflareError("DNS 名称包含无效标签；记录名称可使用下划线前缀，通配符只能位于最左侧，目标域名不能包含下划线。", 422) from None
        if not _LABEL.fullmatch(encoded) or len(prefix + encoded) > 63:
            raise CloudflareError("DNS 名称标签无效或超过 63 个字符。", 422)
        labels.append(prefix + encoded)
    result = ".".join(labels)
    if len(result) > 253:
        raise CloudflareError("DNS 名称转换后超过 253 个字符。", 422)
    return result


def normalize_record(data: DnsRecordInput | dict, zone_name: str) -> dict:
    """Normalize an apex, relative prefix, or an existing in-zone full name."""
    data = data if isinstance(data, DnsRecordInput) else DnsRecordInput.model_validate(data)
    zone = _domain(zone_name)
    if "." not in zone:
        raise CloudflareError("Cloudflare 区域域名无效。", 422)
    raw_name = data.name.strip()
    if raw_name == "@":
        name = zone
    else:
        name = _domain(raw_name, wildcard=True, underscore_labels=True)
        explicit_fqdn = raw_name.endswith((".", "\u3002", "\uff0e", "\uff61"))
        if name == zone or name.endswith("." + zone):
            pass
        elif not explicit_fqdn:
            # A prefix can contain multiple labels. Without a trailing dot,
            # even domain-looking input is relative to the selected zone.
            name += "." + zone
        else:
            raise CloudflareError("带末尾点的完整记录名称不属于当前区域。请填写 @、相对前缀，或当前区域内的完整域名。", 422)
        if len(name) > 253:
            raise CloudflareError("完整 DNS 名称超过 253 个字符。", 422)
    content = data.content
    if data.type in {"A", "AAAA"}:
        expected = 4 if data.type == "A" else 6
        try:
            if "%" in content:
                raise ValueError
            address = ipaddress.ip_address(content.strip())
            if address.version != expected:
                raise ValueError
        except ValueError:
            raise CloudflareError(f"{data.type} 记录内容必须是有效的 IPv{expected} 地址。", 422) from None
        content = str(address)
    elif data.type in {"CNAME", "MX"}:
        content = _domain(content)
        try:
            ipaddress.ip_address(content)
        except ValueError:
            pass
        else:
            raise CloudflareError("CNAME 和 MX 记录目标必须填写域名，不能填写 IP 地址。", 422)
        if "." not in content:
            raise CloudflareError("CNAME 和 MX 记录目标必须填写完整域名。", 422)
    # TXT content is intentionally returned byte-for-byte as entered, including
    # whitespace, quotes and newlines. Empty strings fail model validation.
    if data.proxied and data.type not in {"A", "AAAA", "CNAME"}:
        raise CloudflareError("仅 A、AAAA 和 CNAME 记录可开启 Cloudflare 代理；TXT、MX 必须仅 DNS。", 422)
    if data.type == "MX" and data.priority is None:
        raise CloudflareError("MX 记录必须填写优先级（0–65535）。", 422)
    if data.type != "MX" and data.priority is not None:
        raise CloudflareError("只有 MX 记录可以填写优先级。", 422)
    result = {"type": data.type, "name": name, "content": content,
              "ttl": 1 if data.proxied else data.ttl, "proxied": data.proxied}
    if data.type == "MX":
        result["priority"] = data.priority
    # Explicit null clears an existing comment when a record is updated.
    result["comment"] = data.comment
    return result


class CloudflareClient:
    BASE_URL = "https://api.cloudflare.com/client/v4/"
    # The zones endpoint accepts at most 50; this size also works for records.
    PAGE_SIZE = 50
    MAX_PAGES = 10000

    def __init__(self, token: str, account_id: str):
        self.account_id = validate_id(account_id)
        if not isinstance(token, str) or not token.strip() or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise CloudflareError("Cloudflare API 令牌无效，请重新填写。", 422)
        self._token = token
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self):
        if self._http is not None:
            raise CloudflareError("Cloudflare 客户端已在使用中。", 503)
        self._http = httpx.AsyncClient(
            base_url=self.BASE_URL, headers={"Authorization": "Bearer " + self._token},
            timeout=20, trust_env=False, follow_redirects=False,
        )
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        client, self._http = self._http, None
        if client is not None:
            await client.aclose()

    @staticmethod
    def _upstream_error(status: int, codes: set[int] | None = None) -> CloudflareError:
        codes = codes or set()
        if status == 429 or 1015 in codes:
            return CloudflareError("Cloudflare 请求过于频繁，请稍后重试。", 429)
        if status == 401 or codes & {10000, 10001, 9106, 9107, 9109, 6111}:
            return CloudflareError("Cloudflare 认证失败，请检查 API 令牌是否有效。", 422)
        if status == 403:
            return CloudflareError("Cloudflare 权限不足，请检查令牌的区域读取及 DNS 编辑权限和账户范围。", 422)
        if status == 404:
            return CloudflareError("Cloudflare 区域或 DNS 记录不存在，请刷新后重试。", 404)
        if status in {400, 409, 422}:
            return CloudflareError("Cloudflare 拒绝了 DNS 操作，请检查记录内容、重复记录及类型冲突。", 422)
        return CloudflareError("Cloudflare 服务响应异常，请稍后重试。")

    async def _request(self, method: str, path: str, *, params: dict | None = None, payload: dict | None = None) -> dict:
        if self._http is None:
            raise CloudflareError("Cloudflare 客户端尚未连接。", 503)
        try:
            response = await self._http.request(method, path, params=params, json=payload)
        except httpx.TimeoutException:
            raise CloudflareError("连接 Cloudflare 超时，请稍后重试。", 504) from None
        except (httpx.HTTPError, OSError):
            raise CloudflareError("无法连接 Cloudflare，请检查网络后重试。") from None
        try:
            envelope = response.json()
        except (ValueError, UnicodeError):
            if not 200 <= response.status_code < 300:
                raise self._upstream_error(response.status_code) from None
            raise CloudflareError("Cloudflare 返回了无法识别的响应，请稍后重试。") from None
        errors = envelope.get("errors") if isinstance(envelope, dict) else None
        codes = {item["code"] for item in errors if isinstance(item, dict) and type(item.get("code")) is int} if isinstance(errors, list) else set()
        if not 200 <= response.status_code < 300:
            raise self._upstream_error(response.status_code, codes)
        if not isinstance(envelope, dict):
            raise CloudflareError("Cloudflare 返回了无法识别的响应，请稍后重试。")
        if envelope.get("success") is not True:
            raise self._upstream_error(response.status_code, codes)
        if "result" not in envelope:
            raise CloudflareError("Cloudflare 响应缺少操作结果，请刷新后检查。")
        return envelope

    async def _pages(self, path: str, params: dict | None = None) -> list[dict]:
        records = []
        page = 1
        while page <= self.MAX_PAGES:
            envelope = await self._request("GET", path, params={**(params or {}), "page": page, "per_page": self.PAGE_SIZE})
            batch = envelope["result"]
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                raise CloudflareError("Cloudflare 返回的列表格式异常，请稍后重试。")
            records.extend(batch)
            info = envelope.get("result_info")
            if info is not None:
                if not isinstance(info, dict):
                    raise CloudflareError("Cloudflare 返回的分页信息异常。")
                current, total = info.get("page"), info.get("total_pages")
                if total is None:
                    count, per_page = info.get("total_count"), info.get("per_page")
                    if type(count) is not int or count < 0 or type(per_page) is not int or per_page < 1:
                        raise CloudflareError("Cloudflare 返回的分页信息异常。")
                    total = (count + per_page - 1) // per_page
                if type(current) is not int or current != page or type(total) is not int or total < 0 or total > self.MAX_PAGES:
                    raise CloudflareError("Cloudflare 返回的分页信息异常。")
                if page >= total:
                    return records
                if not batch:
                    raise CloudflareError("Cloudflare 分页结果不完整，请稍后重试。")
            elif len(batch) < self.PAGE_SIZE:
                return records
            page += 1
        raise CloudflareError("Cloudflare 列表过大，无法完整读取。")

    def _zone(self, value: dict) -> dict:
        account = value.get("account")
        if not isinstance(account, dict) or account.get("id") != self.account_id:
            raise CloudflareError("该 Cloudflare 区域不属于当前配置的账户。", 403)
        try:
            zone_id = validate_id(value.get("id"))
            name = value["name"]
            if not isinstance(name, str) or not name or len(name) > 253:
                raise ValueError
        except (KeyError, ValueError, CloudflareError):
            raise CloudflareError("Cloudflare 返回的区域信息异常。") from None
        result = {"id": zone_id, "name": name, "account": {"id": self.account_id}}
        if isinstance(value.get("status"), str):
            result["status"] = value["status"]
        return result

    @staticmethod
    def _record(value: object, expected_id: str | None = None) -> dict:
        if not isinstance(value, dict):
            raise CloudflareError("Cloudflare 返回的 DNS 记录格式异常。")
        try:
            record_id = validate_id(value.get("id"))
            if expected_id is not None and record_id != expected_id:
                raise ValueError
            if not all(isinstance(value.get(key), str) for key in ("type", "name", "content")):
                raise ValueError
        except (ValueError, CloudflareError):
            raise CloudflareError("Cloudflare 返回的 DNS 记录格式异常。") from None
        return {key: value[key] for key in _RECORD_FIELDS if key in value}

    async def list_zones(self) -> list[dict]:
        zones = await self._pages("zones", {"account.id": self.account_id})
        return [self._zone(zone) for zone in zones if isinstance(zone.get("account"), dict) and zone["account"].get("id") == self.account_id]

    async def get_zone(self, zone_id: str) -> dict:
        zone_id = validate_id(zone_id)
        envelope = await self._request("GET", "zones/" + zone_id)
        if not isinstance(envelope["result"], dict):
            raise CloudflareError("Cloudflare 返回的区域信息异常。")
        zone = self._zone(envelope["result"])
        if zone["id"] != zone_id:
            raise CloudflareError("Cloudflare 返回的区域编号不匹配。")
        return zone

    async def list_records(self, zone_id: str) -> list[dict]:
        zone_id = validate_id(zone_id)
        return [self._record(record) for record in await self._pages("zones/" + zone_id + "/dns_records")]

    async def get_record(self, zone_id: str, record_id: str) -> dict:
        zone_id, record_id = validate_id(zone_id), validate_id(record_id)
        envelope = await self._request("GET", f"zones/{zone_id}/dns_records/{record_id}")
        return self._record(envelope["result"], record_id)

    async def create_record(self, zone_id: str, payload: dict) -> dict:
        zone_id = validate_id(zone_id)
        envelope = await self._request("POST", f"zones/{zone_id}/dns_records", payload=payload)
        return self._record(envelope["result"])

    async def update_record(self, zone_id: str, record_id: str, payload: dict) -> dict:
        zone_id, record_id = validate_id(zone_id), validate_id(record_id)
        envelope = await self._request("PATCH", f"zones/{zone_id}/dns_records/{record_id}", payload=payload)
        return self._record(envelope["result"], record_id)

    async def delete_record(self, zone_id: str, record_id: str) -> dict:
        zone_id, record_id = validate_id(zone_id), validate_id(record_id)
        envelope = await self._request("DELETE", f"zones/{zone_id}/dns_records/{record_id}")
        result = envelope["result"]
        if not isinstance(result, dict) or result.get("id") != record_id:
            raise CloudflareError("Cloudflare 删除操作响应异常，请刷新记录确认结果。")
        return {"id": record_id}

"""Independent HTTPS DNS observations used when the system answer disagrees.

Each source must return successful, complete A and AAAA queries. These results
are evidence for the caller to compare; this module never decides to deploy.
"""

from __future__ import annotations

import asyncio
import ipaddress

import httpx
import idna


SOURCES = (
    ("AliDNS", "https://dns.alidns.com/resolve"),
    ("DNSPod", "https://doh.pub/dns-query"),
)
QUERY_TIMEOUT_SECONDS = 8
TOTAL_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 256 * 1024
MAX_ANSWER_RECORDS = 256
MAX_CNAME_HOPS = 8


class _DNSResponseError(ValueError):
    """Only fixed, customer-safe messages may be used here."""


def _name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 254 or value != value.strip():
        raise _DNSResponseError("公共 DNS 返回的域名格式无效。")
    value = value.translate(str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."}))
    if value.endswith("."):
        value = value[:-1]
    try:
        result = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        raise _DNSResponseError("公共 DNS 返回的域名格式无效。") from None
    if "." not in result or len(result) > 253:
        raise _DNSResponseError("公共 DNS 返回的域名格式无效。")
    return result


def _parse_response(value: object, domain: str, query_type: int) -> tuple[list[str], str]:
    if not isinstance(value, dict) or type(value.get("Status")) is not int:
        raise _DNSResponseError("公共 DNS 返回了无效响应。")
    status = value["Status"]
    if status == 3:
        raise _DNSResponseError("公共 DNS 尚未解析此域名（NXDOMAIN）。")
    if status != 0:
        raise _DNSResponseError("公共 DNS 查询未成功，请稍后重试。")
    if value.get("TC") not in (None, False):
        raise _DNSResponseError("公共 DNS 响应不完整，暂时无法确认解析。")
    if "Question" in value:
        questions = value["Question"]
        # AliDNS represents one question as an object; DNSPod uses an array.
        if isinstance(questions, dict):
            questions = [questions]
        if (not isinstance(questions, list) or len(questions) != 1 or not isinstance(questions[0], dict)
                or type(questions[0].get("type")) is not int or questions[0]["type"] != query_type
                or _name(questions[0].get("name")) != domain):
            raise _DNSResponseError("公共 DNS 返回的查询信息不匹配。")
    answers = value.get("Answer", [])
    if not isinstance(answers, list) or len(answers) > MAX_ANSWER_RECORDS:
        raise _DNSResponseError("公共 DNS 返回的记录格式无效。")
    by_owner: dict[str, list[dict]] = {}
    for answer in answers:
        if not isinstance(answer, dict) or type(answer.get("type")) is not int:
            raise _DNSResponseError("公共 DNS 返回的记录格式无效。")
        owner = _name(answer.get("name"))
        by_owner.setdefault(owner, []).append(answer)

    owner, visited = domain, set()
    hops = 0
    while True:
        if owner in visited:
            raise _DNSResponseError("公共 DNS 的 CNAME 解析存在循环。")
        visited.add(owner)
        records = by_owner.get(owner, [])
        aliases = {_name(record.get("data")) for record in records if record["type"] == 5}
        addresses = [record for record in records if record["type"] in {1, 28}]
        if len(aliases) > 1 or aliases and addresses:
            raise _DNSResponseError("公共 DNS 的 CNAME 解析存在冲突。")
        if not aliases:
            result = []
            for record in addresses:
                # A wrong-family answer must not masquerade as successful
                # NODATA, which could otherwise hide an unchecked AAAA record.
                if record["type"] != query_type:
                    raise _DNSResponseError("公共 DNS 返回的地址记录类型与查询不匹配。")
                data = record.get("data")
                try:
                    if not isinstance(data, str) or "%" in data:
                        raise ValueError
                    address = ipaddress.ip_address(data)
                    if address.version != (4 if query_type == 1 else 6):
                        raise ValueError
                except ValueError:
                    raise _DNSResponseError("公共 DNS 返回的 IP 地址格式无效。") from None
                result.append(str(address))
            if hops and not result and not _authoritative_nodata(value, owner):
                raise _DNSResponseError("公共 DNS 的 CNAME 解析链不完整。")
            return sorted(set(result)), owner
        if hops >= MAX_CNAME_HOPS:
            raise _DNSResponseError("公共 DNS 的 CNAME 解析链过长。")
        owner = next(iter(aliases))
        hops += 1


def _authoritative_nodata(value: dict, terminal: str) -> bool:
    """A covering SOA is evidence of NODATA after a CNAME, not a missing hop."""
    authority = value.get("Authority", [])
    if not isinstance(authority, list) or len(authority) > MAX_ANSWER_RECORDS:
        return False
    for record in authority:
        if not isinstance(record, dict) or type(record.get("type")) is not int or record["type"] != 6:
            continue
        try:
            zone = _name(record.get("name"))
        except _DNSResponseError:
            continue
        if terminal != zone and not terminal.endswith("." + zone):
            continue
        data = record.get("data")
        if not isinstance(data, str):
            continue
        fields = data.split()
        if len(fields) != 7:
            continue
        try:
            _name(fields[0])
            _name(fields[1])
        except _DNSResponseError:
            continue
        if all(field.isascii() and field.isdigit() and int(field) <= 0xFFFFFFFF for field in fields[2:]):
            return True
    return False


async def _query(client: httpx.AsyncClient, endpoint: str, domain: str, query_type: int) -> tuple[list[str], str]:
    try:
        response = await client.get(endpoint, params={"name": domain, "type": "A" if query_type == 1 else "AAAA"})
    except httpx.TimeoutException:
        raise _DNSResponseError("公共 DNS 查询超时，请稍后重试。") from None
    except (httpx.HTTPError, OSError):
        raise _DNSResponseError("无法连接公共 DNS 服务，请稍后重试。") from None
    if response.status_code != 200:
        raise _DNSResponseError("公共 DNS 服务响应异常，请稍后重试。")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise _DNSResponseError("公共 DNS 响应过大，无法确认解析。")
    try:
        value = response.json()
    except (ValueError, UnicodeError):
        raise _DNSResponseError("公共 DNS 返回了无效响应。") from None
    return _parse_response(value, domain, query_type)


async def _source(client: httpx.AsyncClient, source: str, endpoint: str, domain: str) -> dict:
    results = await asyncio.gather(_query(client, endpoint, domain, 1), _query(client, endpoint, domain, 28), return_exceptions=True)
    errors = [value for value in results if isinstance(value, BaseException)]
    if errors:
        for error in errors:
            if isinstance(error, asyncio.CancelledError):
                raise error
        message = next((str(error) for error in errors if isinstance(error, _DNSResponseError)), "公共 DNS 返回了无效响应。")
        return {"source": source, "addresses": [], "error": message}
    if results[0][1] != results[1][1]:
        return {"source": source, "addresses": [], "error": "公共 DNS 的 A 与 AAAA 解析链不一致。"}
    addresses = sorted(set(results[0][0] + results[1][0]))
    return {"source": source, "addresses": addresses, "error": None}


def _failed(message: str) -> list[dict]:
    return [{"source": source, "addresses": [], "error": message} for source, _ in SOURCES]


async def resolve_public_dns(domain: str) -> list[dict]:
    """Return two independent observations; failures are never a passing result."""
    try:
        normalized = _name(domain)
    except _DNSResponseError:
        return _failed("待查询的域名格式无效。")

    async def observe():
        async with httpx.AsyncClient(timeout=QUERY_TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
                                     headers={"Accept": "application/dns-json", "Cache-Control": "no-cache"}) as client:
            return await asyncio.gather(*(_source(client, source, endpoint, normalized) for source, endpoint in SOURCES))

    try:
        return await asyncio.wait_for(observe(), TOTAL_TIMEOUT_SECONDS)
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        return _failed("公共 DNS 查询超时，请稍后重试。")
    except Exception:
        return _failed("公共 DNS 查询失败，请稍后重试。")

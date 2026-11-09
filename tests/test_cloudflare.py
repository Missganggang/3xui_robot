import asyncio
import json

import httpx
from pydantic import ValidationError
import pytest

from app import cloudflare as cf


ACCOUNT = "a" * 32
OTHER_ACCOUNT = "b" * 32
ZONE = "c" * 32
OTHER_ZONE = "d" * 32
RECORD = "e" * 32
OTHER_RECORD = "f" * 32
TOKEN = "test-only-token-never-publish"


def zone(zone_id=ZONE, account_id=ACCOUNT):
    return {"id": zone_id, "name": "example.com", "status": "active",
            "account": {"id": account_id, "name": "private-account-name"},
            "private_metadata": "do-not-publish"}


def record(record_id=RECORD):
    return {"id": record_id, "type": "A", "name": "www.example.com",
            "content": "192.168.1.2", "ttl": 300, "proxied": False,
            "comment": "private LAN", "meta": {"private": "do-not-publish"}}


def success(value, *, info=None):
    data = {"success": True, "errors": [], "result": value}
    if info is not None:
        data["result_info"] = info
    return httpx.Response(200, json=data)


@pytest.fixture
def transport_client(monkeypatch):
    original = httpx.AsyncClient
    configurations = []

    def build(handler):
        def factory(**kwargs):
            configurations.append(kwargs.copy())
            return original(**kwargs, transport=httpx.MockTransport(handler))
        monkeypatch.setattr(cf.httpx, "AsyncClient", factory)
        return configurations

    return build


def test_zone_pagination_filters_account_and_uses_fixed_secure_client(transport_client):
    requests = []
    def handler(request):
        requests.append(request)
        assert request.url.scheme == "https" and request.url.host == "api.cloudflare.com"
        assert request.url.path == "/client/v4/zones"
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        assert request.url.params["account.id"] == ACCOUNT
        assert request.url.params["per_page"] == "50"
        page = int(request.url.params["page"])
        values = [zone(), zone(OTHER_ZONE, OTHER_ACCOUNT)] if page == 1 else [zone(OTHER_ZONE)]
        return success(values, info={"page": page, "total_pages": 2})
    configurations = transport_client(handler)
    async def run():
        client = cf.CloudflareClient(TOKEN, ACCOUNT)
        async with client:
            result = await client.list_zones()
            assert len(result) == 2
            assert [item["id"] for item in result] == [ZONE, OTHER_ZONE]
            assert all(item["account"] == {"id": ACCOUNT} for item in result)
            assert "private" not in json.dumps(result)
            http_client = client._http
        assert client._http is None and http_client.is_closed
    asyncio.run(run())
    assert len(requests) == 2
    assert configurations[0]["base_url"] == "https://api.cloudflare.com/client/v4/"
    assert configurations[0]["trust_env"] is False
    assert configurations[0]["follow_redirects"] is False
    assert configurations[0]["timeout"] == 20


@pytest.mark.parametrize("metadata", ["total_pages", "total_count", "absent"])
def test_record_pagination_does_not_drop_later_pages(transport_client, monkeypatch, metadata):
    pages = []
    def handler(request):
        assert request.url.path == f"/client/v4/zones/{ZONE}/dns_records"
        page = int(request.url.params["page"])
        pages.append(page)
        batch = [record(), record(OTHER_RECORD)] if page == 1 else [record("1" * 32)]
        info = {"page": page, "total_pages": 2} if metadata == "total_pages" else {
            "page": page, "per_page": 2, "total_count": 3} if metadata == "total_count" else None
        return success(batch, info=info)
    transport_client(handler)
    monkeypatch.setattr(cf.CloudflareClient, "PAGE_SIZE", 2)
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            result = await client.list_records(ZONE)
            assert len(result) == 3 and all("meta" not in item for item in result)
    asyncio.run(run())
    assert pages == [1, 2]


@pytest.mark.parametrize("foreign", [False, True])
def test_get_zone_checks_account_locally_even_if_token_can_see_other_accounts(transport_client, foreign):
    transport_client(lambda request: success(zone(account_id=OTHER_ACCOUNT if foreign else ACCOUNT)))
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            if foreign:
                with pytest.raises(cf.CloudflareError, match="不属于") as error:
                    await client.get_zone(ZONE)
                assert error.value.status_code == 403
            else:
                assert (await client.get_zone(ZONE))["id"] == ZONE
    asyncio.run(run())


def test_crud_serializes_normalized_payload_and_never_exposes_extra_metadata(transport_client):
    requests = []
    payload = cf.normalize_record({"type": "A", "name": "www", "content": "192.168.1.2", "ttl": 300}, "example.com")
    def handler(request):
        requests.append(request)
        if request.method in {"POST", "PATCH"}:
            assert json.loads(request.content) == payload
        if request.method == "DELETE":
            return success({"id": RECORD, "metadata": "do-not-publish"})
        return success(record())
    transport_client(handler)
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            assert (await client.create_record(ZONE, payload))["id"] == RECORD
            assert (await client.get_record(ZONE, RECORD))["content"] == "192.168.1.2"
            assert (await client.update_record(ZONE, RECORD, payload))["name"] == "www.example.com"
            assert await client.delete_record(ZONE, RECORD) == {"id": RECORD}
    asyncio.run(run())
    assert [request.method for request in requests] == ["POST", "GET", "PATCH", "DELETE"]
    assert requests[0].url.path == f"/client/v4/zones/{ZONE}/dns_records"
    assert all(request.url.path == f"/client/v4/zones/{ZONE}/dns_records/{RECORD}" for request in requests[1:])


@pytest.mark.parametrize("status,code,message,expected", [
    (401, None, "认证失败", 422), (403, None, "权限不足", 422),
    (429, None, "过于频繁", 429), (404, None, "不存在", 404),
    (400, None, "拒绝", 422), (409, None, "拒绝", 422),
    (503, None, "响应异常", 502), (200, 10000, "认证失败", 422),
    (200, 1015, "过于频繁", 429),
])
def test_error_messages_are_classified_and_do_not_echo_upstream_secrets(transport_client, status, code, message, expected):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={"success": False, "errors": [
            {"code": code, "message": f"Authorization: Bearer {TOKEN}; private/raw/detail"}], "result": None})
    transport_client(handler)
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            with pytest.raises(cf.CloudflareError, match=message) as error:
                await client.create_record(ZONE, {"type": "A"})
            assert error.value.status_code == expected
            assert TOKEN not in str(error.value) and "private/raw/detail" not in str(error.value)
            assert error.value.__suppress_context__ or "Bearer" not in str(error.value)
    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize("exception,expected,message", [
    (httpx.ReadTimeout, 504, "超时"), (httpx.ConnectError, 502, "无法连接"),
])
def test_network_failures_are_safe_and_writes_are_never_retried(transport_client, exception, expected, message):
    calls = []
    def handler(request):
        calls.append(request)
        raise exception(TOKEN + " private network detail", request=request)
    transport_client(handler)
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            with pytest.raises(cf.CloudflareError, match=message) as error:
                await client.update_record(ZONE, RECORD, {"type": "A"})
            assert error.value.status_code == expected and TOKEN not in str(error.value)
    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize("response,expected", [
    (lambda: httpx.Response(302, headers={"Location": "https://attacker.invalid/"}, text=TOKEN), 502),
    (lambda: httpx.Response(200, text=TOKEN), 502),
    (lambda: httpx.Response(200, json=[]), 502),
    (lambda: httpx.Response(403, json=[]), 422),
    (lambda: httpx.Response(200, json={"success": True}), 502),
    (lambda: success("bad-result"), 502),
])
def test_redirects_and_malformed_responses_fail_safely(transport_client, response, expected):
    calls = []
    def handler(request):
        calls.append(request)
        return response()
    transport_client(handler)
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            with pytest.raises(cf.CloudflareError) as error:
                await client.get_record(ZONE, RECORD)
            assert error.value.status_code == expected and TOKEN not in str(error.value)
    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize("info", [
    {"page": 2, "total_pages": 2}, {"page": True, "total_pages": 1},
    {"page": 1, "total_pages": -1}, {"page": 1, "total_pages": 20000},
    {"page": 1, "total_count": 3, "per_page": 0},
])
def test_bad_pagination_is_not_reported_as_complete(transport_client, info):
    transport_client(lambda request: success([record()], info=info))
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            with pytest.raises(cf.CloudflareError, match="分页"):
                await client.list_records(ZONE)
    asyncio.run(run())


@pytest.mark.parametrize("bad_id", ["../zones", "", "a" * 31, "g" * 32, None, 123])
def test_invalid_ids_never_issue_http_requests(transport_client, bad_id):
    calls = []
    transport_client(lambda request: calls.append(request))
    async def run():
        async with cf.CloudflareClient(TOKEN, ACCOUNT) as client:
            with pytest.raises(cf.CloudflareError) as error:
                await client.delete_record(ZONE, bad_id)
            assert error.value.status_code == 422
    asyncio.run(run())
    assert calls == []


@pytest.mark.parametrize("token", ["", " ", "abc\r\nsecret", "abc def", None])
def test_invalid_token_is_rejected_without_echo(token):
    with pytest.raises(cf.CloudflareError, match="令牌无效") as error:
        cf.CloudflareClient(token, ACCOUNT)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("data,expected_name,expected_content", [
    ({"type": "A", "name": "@", "content": "10.0.0.1"}, "example.com", "10.0.0.1"),
    ({"type": "AAAA", "name": "WWW", "content": "fd00:0:0:0::1"}, "www.example.com", "fd00::1"),
    ({"type": "A", "name": "aaa", "content": "10.0.0.1"}, "aaa.example.com", "10.0.0.1"),
    ({"type": "A", "name": "foo.bar", "content": "10.0.0.1"}, "foo.bar.example.com", "10.0.0.1"),
    ({"type": "A", "name": "foo.other.com", "content": "10.0.0.1"}, "foo.other.com.example.com", "10.0.0.1"),
    ({"type": "A", "name": "evil-example.com", "content": "10.0.0.1"}, "evil-example.com.example.com", "10.0.0.1"),
    ({"type": "A", "name": "example.com.evil.net", "content": "10.0.0.1"}, "example.com.evil.net.example.com", "10.0.0.1"),
    ({"type": "A", "name": "example.com", "content": "10.0.0.1"}, "example.com", "10.0.0.1"),
    ({"type": "CNAME", "name": "*", "content": "CDN.Example.Net."}, "*.example.com", "cdn.example.net"),
    ({"type": "CNAME", "name": "selector._domainkey.example.com", "content": "dkim.example.net"}, "selector._domainkey.example.com", "dkim.example.net"),
    ({"type": "CNAME", "name": "selector._domainkey", "content": "dkim.example.net"}, "selector._domainkey.example.com", "dkim.example.net"),
    ({"type": "CNAME", "name": "*.apps", "content": "cdn.example.net"}, "*.apps.example.com", "cdn.example.net"),
    ({"type": "CNAME", "name": "_acme-challenge", "content": "challenge.example.net"}, "_acme-challenge.example.com", "challenge.example.net"),
    ({"type": "A", "name": "_service", "content": "10.0.0.1"}, "_service.example.com", "10.0.0.1"),
    ({"type": "A", "name": "a.b.example.com.", "content": "127.0.0.1"}, "a.b.example.com", "127.0.0.1"),
    ({"type": "TXT", "name": "_acme-challenge", "content": "  \"verify\"\n "}, "_acme-challenge.example.com", "  \"verify\"\n "),
    ({"type": "TXT", "name": "selector._domainkey.example.com", "content": " "}, "selector._domainkey.example.com", " "),
    ({"type": "MX", "name": "@", "content": "MAIL.example.net.", "priority": 0}, "example.com", "mail.example.net"),
])
def test_normalization_supports_dns_names_private_addresses_and_original_txt(data, expected_name, expected_content):
    result = cf.normalize_record(data, "EXAMPLE.com.")
    assert result["name"] == expected_name and result["content"] == expected_content
    assert result["ttl"] == 1 and result["proxied"] is False


def test_unicode_idna_and_equivalent_dots_are_normalized_before_zone_boundary_check():
    result = cf.normalize_record({"type": "CNAME", "name": "WWW。例子。公司。", "content": "目标。例子。公司。"}, "例子.公司")
    assert result["name"] == "www.xn--fsqu00a.xn--55qx5d"
    assert result["content"] == "xn--iwvq54a.xn--fsqu00a.xn--55qx5d"


def test_nested_unicode_prefix_and_existing_name_stay_within_zone_without_double_suffix():
    data = {"type": "A", "name": "WWW。例子", "content": "10.0.0.1"}
    result = cf.normalize_record(data, "公司.example")
    assert result["name"] == "www.xn--fsqu00a.xn--55qx5d.example"
    edited = cf.normalize_record({**data, "name": result["name"]}, "公司.example")
    assert edited["name"] == result["name"]
    assert cf.normalize_record({**data, "name": "@"}, "公司.example")["name"] == "xn--55qx5d.example"


def test_proxied_record_always_uses_automatic_ttl_and_preserves_comment():
    result = cf.normalize_record({"type": "A", "name": "www", "content": "192.168.0.1",
                                  "ttl": 86400, "proxied": True, "comment": "business label"}, "example.com")
    assert result["ttl"] == 1 and result["proxied"] is True and result["comment"] == "business label"


@pytest.mark.parametrize("change", [
    {"name": "evil-example.com."}, {"name": "example.com.evil.net."}, {"name": "foo.other.com。"},
    {"name": "outside.net."}, {"name": "www..example.com"}, {"name": "example.com.."},
    {"name": "a.*.example.com"}, {"name": "x*.example.com"},
    {"name": "https://example.com"}, {"name": "-bad"},
    {"content": "2001:db8::1"}, {"content": "999.1.1.1"},
    {"type": "AAAA", "content": "1.1.1.1"}, {"type": "AAAA", "content": "fe80::1%eth0"},
    {"type": "MX", "content": "mail.example.net"},
    {"type": "MX", "content": "mail.example.net", "priority": 10, "proxied": True},
    {"type": "TXT", "content": "test", "proxied": True},
    {"type": "CNAME", "content": "1.2.3.4"},
    {"type": "CNAME", "content": "_invalid.example.net"},
    {"type": "MX", "content": "_invalid.example.net", "priority": 10},
    {"type": "CNAME", "content": "https://example.com"}, {"type": "CNAME", "content": "localhost"},
    {"priority": 0},
])
def test_invalid_record_semantics_raise_customer_safe_422(change):
    data = {"type": "A", "name": "www", "content": "1.1.1.1", **change}
    with pytest.raises(cf.CloudflareError) as error:
        cf.normalize_record(data, "example.com")
    assert error.value.status_code == 422


@pytest.mark.parametrize("change", [
    {"ttl": True}, {"ttl": "300"}, {"ttl": 0}, {"ttl": 59}, {"ttl": 86401},
    {"priority": True}, {"priority": -1}, {"priority": 65536},
    {"proxied": "false"}, {"comment": "x" * 501}, {"name": "x" * 254},
    {"content": "x" * 4097}, {"content": ""}, {"content": 123},
    {"type": "SRV"}, {"unexpected": "forbidden"},
])
def test_strict_pydantic_input_rejects_coercions_and_extra_fields(change):
    with pytest.raises(ValidationError):
        cf.DnsRecordInput.model_validate({"type": "A", "name": "www", "content": "1.1.1.1", **change})


def test_name_length_is_checked_after_idna_expansion_and_apex_completion():
    with pytest.raises(cf.CloudflareError):
        cf.normalize_record({"type": "A", "name": "中" * 60, "content": "1.1.1.1"}, "example.com")
    zone_name = ".".join(["x" * 63] * 3 + ["y" * 60])
    with pytest.raises(cf.CloudflareError, match="253"):
        cf.normalize_record({"type": "A", "name": "www", "content": "1.1.1.1"}, zone_name)

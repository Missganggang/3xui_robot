import asyncio
import httpx
import pytest

from app import public_dns as dns


DOMAIN = "panel.example.com"
TARGET = "203.0.113.10"


def answer(name=DOMAIN, kind=1, data=TARGET):
    return {"name": name, "type": kind, "TTL": 300, "data": data}


def envelope(records=None, **extra):
    result = {"Status": 0, **extra}
    if records is not None:
        result["Answer"] = records
    return result


@pytest.fixture
def use_transport(monkeypatch):
    original = httpx.AsyncClient
    settings, clients = [], []
    def use(handler):
        def factory(**kwargs):
            settings.append(kwargs.copy())
            client = original(**kwargs, transport=httpx.MockTransport(handler))
            clients.append(client)
            return client
        monkeypatch.setattr(dns.httpx, "AsyncClient", factory)
        return settings, clients
    return use


def test_four_queries_are_parallel_fixed_https_and_safe_client_is_closed(use_transport):
    started, requests = [], []
    async def run():
        all_started = asyncio.Event()
        async def handler(request):
            started.append((request.url.host, request.url.params["type"]))
            requests.append(request)
            if len(started) == 4:
                all_started.set()
            await asyncio.wait_for(all_started.wait(), 0.5)
            assert request.url.params["name"] == DOMAIN
            assert request.headers["Accept"] == "application/dns-json"
            assert request.headers["Cache-Control"] == "no-cache"
            return httpx.Response(200, json=envelope([answer()] if request.url.params["type"] == "A" else None))
        settings, clients = use_transport(handler)
        result = await dns.resolve_public_dns(DOMAIN)
        assert result == [
            {"source": "AliDNS", "addresses": [TARGET], "error": None},
            {"source": "DNSPod", "addresses": [TARGET], "error": None},
        ]
        assert clients[0].is_closed
        assert settings == [{"timeout": 8, "trust_env": False, "follow_redirects": False,
                             "headers": {"Accept": "application/dns-json", "Cache-Control": "no-cache"}}]
    asyncio.run(run())
    assert {(request.url.scheme, request.url.host, request.url.path) for request in requests} == {
        ("https", "dns.alidns.com", "/resolve"), ("https", "doh.pub", "/dns-query")}


def test_sources_keep_disagreement_and_ipv6_addresses_are_normalized(use_transport):
    def handler(request):
        is_a = request.url.params["type"] == "A"
        ip = TARGET if request.url.host == "dns.alidns.com" else "198.51.100.20"
        records = [answer(data=ip), answer(data=ip)] if is_a else [answer(kind=28, data="2001:db8:0:0::1")]
        return httpx.Response(200, json=envelope(records))
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert set(result[0]["addresses"]) == {TARGET, "2001:db8::1"}
    assert set(result[1]["addresses"]) == {"198.51.100.20", "2001:db8::1"}
    assert all(item["error"] is None for item in result)


def test_only_query_related_cname_chain_answers_are_collected(use_transport):
    canonical = "origin.example.net"
    def handler(request):
        kind = 1 if request.url.params["type"] == "A" else 28
        records = [answer(name=DOMAIN.upper() + ".", kind=5, data="mid.example.net."),
                   answer(name="mid.example.net", kind=5, data=canonical.upper() + "."),
                   answer(name=canonical, kind=kind, data=TARGET if kind == 1 else "2001:db8::1"),
                   answer(name="unrelated.example.net", data="127.0.0.1")]
        return httpx.Response(200, json=envelope(records, Additional=[answer(data="10.0.0.1")]))
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert all(item["addresses"] == ["2001:db8::1", TARGET] and item["error"] is None for item in result)


def test_cname_nodata_is_complete_only_with_a_covering_authority_soa(use_transport):
    canonical = "origin.example.net"
    def handler(request):
        records = [answer(kind=5, data=canonical)]
        extra = {}
        if request.url.params["type"] == "A":
            records.append(answer(name=canonical))
        else:
            extra["Authority"] = [{"name": "example.net.", "type": 6,
                                   "data": "ns.example.net. hostmaster.example.net. 1 2 3 4 5"}]
        return httpx.Response(200, json=envelope(records, **extra))
    use_transport(handler)
    assert all(item["addresses"] == [TARGET] and item["error"] is None for item in asyncio.run(dns.resolve_public_dns(DOMAIN)))


@pytest.mark.parametrize("bad", [
    {"Status": 3}, {"Status": 2}, {"Status": True}, [],
    {"Status": 0, "Answer": None}, {"Status": 0, "Answer": "invalid"},
    envelope([{"type": 1, "data": TARGET}]), envelope([answer(data="not-an-ip")]),
    envelope([answer(kind=28, data="fe80::1%eth0")]),
    envelope([answer(kind=5, data="origin.example.net")]),
    envelope([answer(kind=5, data=DOMAIN)]),
    envelope([answer(kind=5, data="first.example.net"), answer(kind=5, data="second.example.net")]),
    envelope([answer(kind=5, data="first.example.net"), answer()]),
    envelope([answer()], TC=True),
    envelope([answer()], Question=[{"name": "wrong.example.com", "type": 1}]),
])
def test_invalid_or_incomplete_family_discards_source_not_other_source(use_transport, bad):
    def handler(request):
        if request.url.host == "dns.alidns.com":
            return httpx.Response(200, json=bad)
        return httpx.Response(200, json=envelope([answer()] if request.url.params["type"] == "A" else None))
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert result[0]["addresses"] == [] and result[0]["error"]
    assert result[1] == {"source": "DNSPod", "addresses": [TARGET], "error": None}


@pytest.mark.parametrize("bad_family", ["A", "AAAA"])
def test_wrong_address_family_is_not_accepted_as_empty_answer(use_transport, bad_family):
    def handler(request):
        kind = 1 if request.url.params["type"] == "A" else 28
        if request.url.params["type"] == bad_family:
            kind = 28 if kind == 1 else 1
        return httpx.Response(200, json=envelope([answer(kind=kind, data=TARGET if kind == 1 else "2001:db8::1")]))
    use_transport(handler)
    assert all(item["addresses"] == [] and "类型" in item["error"] for item in asyncio.run(dns.resolve_public_dns(DOMAIN)))


@pytest.mark.parametrize("soa", [
    "invalid", "ns.example.net. hostmaster.example.net. 1 2 3 4 -1",
    "ns.example.net. hostmaster.example.net. 1 2 3 4 4294967296",
    "not-a-domain hostmaster.example.net. 1 2 3 4 5",
])
def test_malformed_soa_cannot_complete_missing_cname_family(use_transport, soa):
    def handler(request):
        return httpx.Response(200, json=envelope([answer(kind=5, data="origin.example.net")],
            Authority=[{"name": "example.net", "type": 6, "data": soa}]))
    use_transport(handler)
    assert all(item["addresses"] == [] and "不完整" in item["error"] for item in asyncio.run(dns.resolve_public_dns(DOMAIN)))


@pytest.mark.parametrize("broken_family", ["A", "AAAA"])
def test_one_failed_family_cannot_be_reported_as_successful_source(use_transport, broken_family):
    def handler(request):
        if request.url.host == "dns.alidns.com" and request.url.params["type"] == broken_family:
            raise httpx.ReadTimeout("private query response token=secret", request=request)
        return httpx.Response(200, json=envelope([answer()] if request.url.params["type"] == "A" else None))
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert result[0]["addresses"] == [] and "超时" in result[0]["error"]
    assert result[1]["addresses"] == [TARGET] and result[1]["error"] is None
    assert "private" not in str(result) and "secret" not in str(result)


@pytest.mark.parametrize("failure", ["network", "redirect", "json", "http", "oversize"])
def test_http_failures_do_not_follow_redirects_or_echo_upstream_text(use_transport, failure):
    calls = []
    def handler(request):
        calls.append(request)
        if failure == "network":
            raise httpx.ConnectError("private raw token=secret", request=request)
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://attacker.invalid/?token=secret"}, text="private raw")
        if failure == "json":
            return httpx.Response(200, text="private raw token=secret")
        if failure == "oversize":
            return httpx.Response(200, content=b"x" * (dns.MAX_RESPONSE_BYTES + 1))
        return httpx.Response(503, text="private raw token=secret")
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert len(calls) == 4
    assert all(item["error"] and item["addresses"] == [] for item in result)
    assert "private" not in str(result) and "secret" not in str(result)


@pytest.mark.parametrize("hops", [8, 9])
def test_cname_chain_has_bounded_length(use_transport, hops):
    def handler(request):
        records = []
        previous = DOMAIN
        for index in range(hops):
            current = f"hop{index}.example.net"
            records.append(answer(name=previous, kind=5, data=current))
            previous = current
        kind = 1 if request.url.params["type"] == "A" else 28
        records.append(answer(name=previous, kind=kind, data=TARGET if kind == 1 else "2001:db8::1"))
        return httpx.Response(200, json=envelope(records))
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert all((item["error"] is None) == (hops == 8) for item in result)


def test_inconsistent_a_aaaa_cname_terminals_do_not_pass(use_transport):
    def handler(request):
        kind = 1 if request.url.params["type"] == "A" else 28
        name = f"origin{kind}.example.net"
        return httpx.Response(200, json=envelope([answer(kind=5, data=name),
            answer(name=name, kind=kind, data=TARGET if kind == 1 else "2001:db8::1")]))
    use_transport(handler)
    assert all("不一致" in item["error"] for item in asyncio.run(dns.resolve_public_dns(DOMAIN)))


def test_global_deadline_cancels_all_requests_and_returns_errors(use_transport, monkeypatch):
    cancelled = []
    async def handler(request):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(request.url.host)
    _, clients = use_transport(handler)
    monkeypatch.setattr(dns, "TOTAL_TIMEOUT_SECONDS", 0.02)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert len(cancelled) == 4
    assert all(item["addresses"] == [] and "超时" in item["error"] for item in result)
    assert clients[0].is_closed


def test_caller_cancellation_propagates_and_closes_client(use_transport):
    async def run():
        entered = asyncio.Event()
        async def handler(request):
            entered.set()
            await asyncio.Event().wait()
        _, clients = use_transport(handler)
        task = asyncio.create_task(dns.resolve_public_dns(DOMAIN))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert clients[0].is_closed
    asyncio.run(run())


@pytest.mark.parametrize("domain", ["", "localhost", "bad..example.com", "https://example.com", None])
def test_invalid_domain_returns_safe_results_without_request(use_transport, domain):
    called = []
    use_transport(lambda request: called.append(request))
    result = asyncio.run(dns.resolve_public_dns(domain))
    assert all(item["addresses"] == [] and item["error"] for item in result)
    assert called == []


def test_question_normalization_and_ipv6_only_domain_are_supported(use_transport):
    def handler(request):
        kind = 1 if request.url.params["type"] == "A" else 28
        return httpx.Response(200, json=envelope([answer(kind=28, data="2001:4860:0:0::8888")] if kind == 28 else [],
            Question=[{"name": DOMAIN.upper() + ".", "type": kind}]))
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN.upper() + "."))
    assert all(item["error"] is None and item["addresses"] == ["2001:4860::8888"] for item in result)


def test_alidns_object_question_and_dnspod_array_question_both_accept_complete_answers(use_transport):
    def handler(request):
        kind = 1 if request.url.params["type"] == "A" else 28
        question = {"name": DOMAIN + ".", "type": kind}
        value = envelope([answer()] if kind == 1 else None,
            Question=question if request.url.host == "dns.alidns.com" else [question])
        if kind == 28:
            value["Authority"] = [{"name": "example.com.", "type": 6,
                "data": "ollie.ns.cloudflare.com. dns.cloudflare.com. 2419621770 10000 2400 604800 1800"}]
        return httpx.Response(200, json=value)
    use_transport(handler)
    result = asyncio.run(dns.resolve_public_dns(DOMAIN))
    assert all(item["addresses"] == [TARGET] and item["error"] is None for item in result)

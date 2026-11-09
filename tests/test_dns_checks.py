import asyncio
from unittest.mock import AsyncMock

import pytest

from app import remote


DOMAIN = "panel.example.com"
TARGET = "8.8.8.8"
OLD_IP = "1.1.1.1"


def public_answers(first=None, second=None):
    return [
        {"source": source, "addresses": addresses, "error": None}
        for source, addresses in zip(("AliDNS", "DNSPod"), (
            [TARGET] if first is None else first,
            [TARGET] if second is None else second,
        ))
    ]


def run_check(tmp_path, monkeypatch, local, public):
    async def scenario():
        system = AsyncMock()
        if isinstance(local, BaseException):
            system.side_effect = local
        else:
            system.return_value = [(2, 1, 6, "", (ip, 0)) for ip in local]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", system)
        fallback = AsyncMock(return_value=public)
        monkeypatch.setattr(remote, "resolve_public_dns", fallback)
        emit = AsyncMock()
        await remote._check_dns(
            {"domain": DOMAIN, "server_ip": TARGET},
            remote.RemoteOptions(tmp_path / "known_hosts"), emit)
        return fallback, emit
    return asyncio.run(scenario())


def test_matching_local_dns_avoids_public_dependency(tmp_path, monkeypatch):
    fallback, emit = run_check(tmp_path, monkeypatch, [TARGET], [])
    fallback.assert_not_awaited()
    assert TARGET in str(emit.await_args_list)


@pytest.mark.parametrize("local", [[OLD_IP], ["127.0.0.1"], [], OSError("private resolver error"), asyncio.TimeoutError()])
def test_two_matching_public_sources_recover_stale_or_failed_local_dns(tmp_path, monkeypatch, local):
    fallback, emit = run_check(tmp_path, monkeypatch, local, public_answers())
    fallback.assert_awaited_once_with(DOMAIN)
    log = str(emit.await_args_list)
    assert all(value in log for value in (DOMAIN, TARGET, "AliDNS", "DNSPod", "已通过公网核验"))
    assert "private resolver error" not in log
    if local == [OLD_IP]:
        assert OLD_IP in log


@pytest.mark.parametrize("public,reason", [
    (public_answers([OLD_IP], [OLD_IP]), "尚未一致指向"),
    (public_answers([TARGET], [OLD_IP]), "尚未一致指向"),
    (public_answers([TARGET, "2606:4700:4700::1111"]), "其他 IP"),
    (public_answers([TARGET, "127.0.0.1"]), "内网或保留地址"),
    (public_answers([], []), "尚未一致指向"),
    ([{"source": "AliDNS", "addresses": [TARGET], "error": None}], "核验未完成"),
    ([{"source": "AliDNS", "addresses": [TARGET], "error": None},
      {"source": "DNSPod", "addresses": [], "error": "AAAA 解析超时"}], "核验未完成"),
])
def test_public_mismatch_or_incomplete_answers_reject_with_diagnostics(tmp_path, monkeypatch, public, reason):
    with pytest.raises(remote.RemoteJobError) as caught:
        run_check(tmp_path, monkeypatch, [OLD_IP], public)
    message = str(caught.value)
    assert all(value in message for value in (DOMAIN, TARGET, OLD_IP, reason, "A / AAAA", "灰云"))


def test_dns_cancel_propagates_without_attempting_public_lookup(tmp_path, monkeypatch):
    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(side_effect=asyncio.CancelledError()))
        public = AsyncMock()
        monkeypatch.setattr(remote, "resolve_public_dns", public)
        with pytest.raises(asyncio.CancelledError):
            await remote._check_dns({"domain": DOMAIN, "server_ip": TARGET}, remote.RemoteOptions(tmp_path / "hosts"))
        public.assert_not_awaited()
    asyncio.run(scenario())


def test_dns_fallback_cancel_propagates(tmp_path, monkeypatch):
    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=[]))
        monkeypatch.setattr(remote, "resolve_public_dns", AsyncMock(side_effect=asyncio.CancelledError()))
        with pytest.raises(asyncio.CancelledError):
            await remote._check_dns({"domain": DOMAIN, "server_ip": TARGET}, remote.RemoteOptions(tmp_path / "hosts"))
    asyncio.run(scenario())

import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app import cloudflare
from app.config import Settings
from app.main import create_app
from app.security import hash_password, secret_box


ACCOUNT = "a" * 32
ZONE = "b" * 32
RECORD = "c" * 32
OTHER_ZONE = "d" * 32
SECOND_ZONE = "1" * 32
TOKEN = "test-only-cloudflare-token"
PASSWORD = "test-only-cloudflare-admin"


@pytest.fixture
def console(tmp_path, monkeypatch, request):
    options = getattr(request, "param", {})
    requests = []
    records = {RECORD: {"id": RECORD, "type": "A", "name": "www.example.com",
                        "content": "192.0.2.10", "ttl": 1, "proxied": False}}
    zone = {"id": ZONE, "name": "example.com", "status": "active", "account": {"id": ACCOUNT}}

    def response(request):
        requests.append(request)
        if request.headers.get("Authorization") != "Bearer " + TOKEN:
            return httpx.Response(403, json={"success": False, "errors": [{"code": 10000, "message": TOKEN}]})
        path = request.url.path.removeprefix("/client/v4")
        if path == "/zones":
            assert request.url.params["account.id"] == ACCOUNT
            zones = [zone]
            if options.get("two_zones"):
                zones.append({**zone, "id": SECOND_ZONE, "name": "second.example"})
            return httpx.Response(200, json={"success": True, "result": zones, "result_info": {"page": 1, "total_pages": 1}})
        if path == f"/zones/{OTHER_ZONE}":
            return httpx.Response(200, json={"success": True, "result": {**zone, "id": OTHER_ZONE, "account": {"id": "e" * 32}}})
        if path == f"/zones/{ZONE}":
            return httpx.Response(200, json={"success": True, "result": zone})
        if path == f"/zones/{SECOND_ZONE}":
            return httpx.Response(200, json={"success": True, "result": {**zone, "id": SECOND_ZONE, "name": "second.example"}})
        if path == f"/zones/{ZONE}/dns_records":
            if request.method == "GET":
                page = int(request.url.params.get("page", "1"))
                size = int(request.url.params.get("per_page", "50"))
                values = list(records.values())
                return httpx.Response(200, json={"success": True, "result": values[(page - 1) * size:page * size], "result_info": {"page": page, "total_pages": (len(values) + size - 1) // size}})
            if request.method == "POST":
                import json
                value = {**json.loads(request.content), "id": uuid.uuid4().hex}
                records[value["id"]] = value
                return httpx.Response(200, json={"success": True, "result": value})
        if path == f"/zones/{ZONE}/dns_records/{RECORD}":
            if request.method == "PATCH":
                import json
                records[RECORD] = {**json.loads(request.content), "id": RECORD}
            if request.method == "DELETE":
                records.pop(RECORD, None)
                return httpx.Response(200, json={"success": True, "result": {"id": RECORD}})
            return httpx.Response(200, json={"success": True, "result": records[RECORD]})
        return httpx.Response(404, json={"success": False, "errors": [{"code": 81044}]})

    async def delayed_response(request):
        result = response(request)
        if options.get("delay") and request.method == "GET" and request.url.path.endswith("/dns_records"):
            # Give a second request time to observe the same pre-write count.
            await asyncio.sleep(0.1)
        return result

    original = httpx.AsyncClient
    monkeypatch.setattr(cloudflare.httpx, "AsyncClient", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(delayed_response)))
    settings = Settings(secret="cloudflare-api-test-secret-" * 3, data_dir=tmp_path,
                        cookie_secure=False, allowed_hosts=("testserver",), enable_worker=False)
    app = create_app(settings)
    app.state.store.add_user("admin", hash_password(PASSWORD), "admin")
    app.state.store.add_user("customer", hash_password(PASSWORD))
    app.state.store.add_user("bob", hash_password(PASSWORD))
    with TestClient(app) as client:
        yield app, client, requests, records


def login(client, username="admin"):
    csrf = client.get("/api/me").json()["csrf_token"]
    response = client.post("/api/login", json={"username": username, "password": PASSWORD}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def configure(client, headers, **changes):
    return client.put("/api/admin/cloudflare", headers=headers,
                      json={"account_id": ACCOUNT, "api_token": TOKEN, **changes})


def test_credentials_are_encrypted_never_returned_and_blank_token_preserves(console):
    app, client, requests, _ = console
    headers = login(client)
    assert client.get("/api/admin/cloudflare").json()["configured"] is False
    response = configure(client, headers)
    assert response.status_code == 200, response.text
    assert response.json()["configuration"]["account_id"] == ACCOUNT
    assert len(response.json()["zones"]) == 1
    saved = app.state.store.integration("cloudflare")
    assert TOKEN not in saved["encrypted_token"]
    assert secret_box(app.state.settings.secret).decrypt(saved["encrypted_token"].encode()).decode() == TOKEN
    for output in (response.text, client.get("/api/admin/cloudflare").text):
        assert TOKEN not in output and saved["encrypted_token"] not in output
    response = client.put("/api/admin/cloudflare", headers=headers, json={"account_id": ACCOUNT, "api_token": ""})
    assert response.status_code == 200
    assert len(requests) == 2


def test_bad_token_does_not_overwrite_working_configuration_or_expose_token(console):
    app, client, _, _ = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    before = copy.deepcopy(app.state.store.integration("cloudflare"))
    response = configure(client, headers, api_token="invalid-test-token")
    assert response.status_code == 422
    assert TOKEN not in response.text and "invalid-test-token" not in response.text
    assert app.state.store.integration("cloudflare") == before
    assert client.get("/api/me").json()["user"]["role"] == "admin"


def test_dns_crud_normalizes_zone_and_preserves_content(console):
    _, client, requests, records = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    assert len(client.get("/api/admin/cloudflare/zones").json()["zones"]) == 1
    endpoint = f"/api/admin/cloudflare/zones/{ZONE}/records"
    response = client.get(endpoint)
    assert response.status_code == 200 and response.json()["records"][0]["id"] == RECORD
    response = client.post(endpoint, headers=headers, json={"type": "TXT", "name": "@", "content": "  verification-value  ", "ttl": 300, "proxied": False})
    assert response.status_code == 201, response.text
    assert response.json()["record"]["name"] == "example.com"
    assert response.json()["record"]["content"] == "  verification-value  "
    response = client.put(endpoint + "/" + RECORD, headers=headers, json={"type": "A", "name": "www", "content": "192.0.2.20", "ttl": 300, "proxied": False})
    assert response.status_code == 200, response.text
    assert records[RECORD]["content"] == "192.0.2.20"
    response = client.delete(endpoint + "/" + RECORD, headers=headers)
    assert response.status_code == 200 and response.json()["deleted"] is True
    assert RECORD not in records
    assert [request.method for request in requests].count("POST") == 1
    assert [request.method for request in requests].count("PATCH") == 1
    assert [request.method for request in requests].count("DELETE") == 1


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/admin/cloudflare", None),
    ("PUT", "/api/admin/cloudflare", {"account_id": ACCOUNT, "api_token": TOKEN}),
    ("GET", "/api/admin/cloudflare/zones", None),
    ("GET", f"/api/admin/cloudflare/zones/{ZONE}/records", None),
    ("POST", f"/api/admin/cloudflare/zones/{ZONE}/records", {"type": "A", "name": "www", "content": "192.0.2.1"}),
    ("PUT", f"/api/admin/cloudflare/zones/{ZONE}/records/{RECORD}", {"type": "A", "name": "www", "content": "192.0.2.1"}),
    ("DELETE", f"/api/admin/cloudflare/zones/{ZONE}/records/{RECORD}", None),
])
def test_customer_cannot_access_cloudflare_or_trigger_upstream(console, method, path, body):
    _, client, requests, _ = console
    headers = login(client, "customer")
    response = client.request(method, path, headers=headers, json=body)
    assert response.status_code == 403
    assert requests == []


def test_mutations_require_csrf_and_zone_must_belong_to_configured_account(console):
    _, client, requests, _ = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    requests.clear()
    endpoint = f"/api/admin/cloudflare/zones/{ZONE}/records"
    payload = {"type": "A", "name": "www", "content": "192.0.2.1"}
    for method, path, body in [("PUT", "/api/admin/cloudflare", {"account_id": ACCOUNT, "api_token": TOKEN}),
                               ("POST", endpoint, payload), ("PUT", endpoint + "/" + RECORD, payload),
                               ("DELETE", endpoint + "/" + RECORD, None)]:
        assert client.request(method, path, json=body).status_code == 403
    assert requests == []
    other = f"/api/admin/cloudflare/zones/{OTHER_ZONE}/records"
    response = client.post(other, headers=headers, json=payload)
    assert response.status_code in (403, 404, 422)
    assert all(request.method == "GET" for request in requests)


def test_unconfigured_corrupt_credentials_and_invalid_inputs_are_clear(console):
    app, client, requests, _ = console
    headers = login(client)
    response = client.get("/api/admin/cloudflare/zones")
    assert response.status_code == 409
    app.state.store.save_integration("cloudflare", ACCOUNT, "damaged-ciphertext")
    assert client.get("/api/admin/cloudflare/zones").status_code == 409
    assert configure(client, headers).status_code == 200
    requests.clear()
    response = client.post(f"/api/admin/cloudflare/zones/{ZONE}/records", headers=headers,
                           json={"type": "A", "name": "outside.example.net", "content": "not-an-ip"})
    assert response.status_code == 422
    assert all(request.method == "GET" for request in requests)
    response = client.delete(f"/api/admin/cloudflare/zones/{ZONE}/records/bad-id", headers=headers)
    assert response.status_code == 422
    assert all(request.method == "GET" for request in requests)


def assign(client, headers, user_id, zone_ids):
    return client.put(f"/api/admin/users/{user_id}/domains", headers=headers, json={"zone_ids": zone_ids})


@pytest.mark.parametrize("console", [{"two_zones": True}], indirect=True)
def test_customer_zone_assignment_is_explicit_scoped_and_revocable(console):
    app, client, requests, _ = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    customer = app.state.store.user_by_name("customer")
    bob = app.state.store.user_by_name("bob")
    domains_path = f"/api/admin/users/{customer['id']}/domains"
    data = client.get(domains_path).json()
    assert data["assigned_zone_ids"] == [] and len(data["zones"]) == 2
    assert assign(client, headers, customer["id"], [ZONE]).status_code == 200
    assert client.get(domains_path).json()["assigned_zone_ids"] == [ZONE]
    customer_headers = login(client, "customer")
    data = client.get("/api/dns/zones").json()
    assert [zone["id"] for zone in data["zones"]] == [ZONE]
    assert data["record_limit"] == 100
    assert "account" not in data["zones"][0] and TOKEN not in str(data)
    requests.clear()
    for method, path, body in [
        ("GET", f"/api/dns/zones/{SECOND_ZONE}/records", None),
        ("POST", f"/api/dns/zones/{SECOND_ZONE}/records", {"type": "A", "name": "www", "content": "192.0.2.1"}),
        ("PUT", f"/api/dns/zones/{SECOND_ZONE}/records/{RECORD}", {"type": "A", "name": "www", "content": "192.0.2.1"}),
        ("DELETE", f"/api/dns/zones/{SECOND_ZONE}/records/{RECORD}", None),
        ("GET", domains_path, None),
        ("PUT", domains_path, {"zone_ids": [SECOND_ZONE]}),
        ("PUT", f"/api/admin/users/{bob['id']}/domains", {"zone_ids": [ZONE]}),
    ]:
        assert client.request(method, path, headers=customer_headers, json=body).status_code == 403
    assert requests == []
    headers = login(client)
    assert assign(client, headers, customer["id"], []).status_code == 200
    login(client, "customer")
    requests.clear()
    assert client.get("/api/dns/zones").json()["zones"] == []
    assert client.get(f"/api/dns/zones/{ZONE}/records").status_code == 403
    assert requests == []


def test_new_and_existing_customers_start_without_domains_even_when_cloudflare_is_unconfigured(console):
    app, client, requests, _ = console
    login(client, "customer")
    assert client.get("/api/dns/zones").json() == {"zones": [], "record_limit": 100}
    headers = login(client)
    created = client.post("/api/admin/users", headers=headers, json={"username": "new-customer", "password": PASSWORD})
    assert created.status_code == 201
    assert app.state.store.user_domains(created.json()["user"]["id"], ACCOUNT) == []
    login(client, "new-customer")
    assert client.get("/api/dns/zones").json()["zones"] == []
    assert requests == []


def test_assigned_customer_can_create_edit_delete_but_not_change_configuration(console):
    app, client, _, records = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    customer = app.state.store.user_by_name("customer")
    assert assign(client, headers, customer["id"], [ZONE]).status_code == 200
    headers = login(client, "customer")
    endpoint = f"/api/dns/zones/{ZONE}/records"
    data = client.get(endpoint).json()
    assert data["record_limit"] == 100 and "account" not in data["zone"]
    response = client.post(endpoint, headers=headers, json={"type": "A", "name": "aaa", "content": "192.0.2.33"})
    assert response.status_code == 201 and response.json()["record"]["name"] == "aaa.example.com"
    response = client.put(endpoint + "/" + RECORD, headers=headers, json={"type": "A", "name": "nested.sub", "content": "192.0.2.34"})
    assert response.status_code == 200 and records[RECORD]["name"] == "nested.sub.example.com"
    assert client.delete(endpoint + "/" + RECORD, headers=headers).status_code == 200
    assert client.get("/api/admin/cloudflare").status_code == 403
    assert configure(client, headers).status_code == 403
    login(client, "bob")
    assert client.get("/api/dns/zones").json()["zones"] == []
    assert client.get(endpoint).status_code == 403


def test_assignments_validate_scope_csrf_and_configuration_changes_clear_grants(console):
    app, client, requests, _ = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    customer = app.state.store.user_by_name("customer")
    endpoint = f"/api/admin/users/{customer['id']}/domains"
    assert client.put(endpoint, json={"zone_ids": [ZONE]}).status_code == 403
    assert assign(client, headers, customer["id"], [OTHER_ZONE]).status_code == 422
    assert assign(client, headers, customer["id"], ["bad-id"]).status_code == 422
    assert assign(client, headers, app.state.store.user_by_name("admin")["id"], [ZONE]).status_code == 404
    assert assign(client, headers, customer["id"], [ZONE, ZONE]).status_code == 200
    assert len(app.state.store.user_domains(customer["id"], ACCOUNT)) == 1
    assert assign(client, headers, customer["id"], [OTHER_ZONE]).status_code == 422
    assert [zone["id"] for zone in app.state.store.user_domains(customer["id"], ACCOUNT)] == [ZONE]
    # A token replacement for the same account keeps explicit grants.
    assert configure(client, headers).status_code == 200
    assert len(app.state.store.user_domains(customer["id"], ACCOUNT)) == 1
    app.state.store.save_integration("cloudflare", "2" * 32, "test-encrypted-placeholder")
    assert app.state.store.user_domains(customer["id"], ACCOUNT) == []
    login(client, "customer")
    requests.clear()
    assert client.get("/api/dns/zones").json()["zones"] == []
    assert requests == []


def fill_records(records, count):
    records.clear()
    for index in range(count):
        key = RECORD if index == 0 else f"{index:032x}"
        records[key] = {"id": key, "type": "TXT", "name": f"r{index}.example.com", "content": f"value-{index}", "ttl": 300, "proxied": False}


@pytest.mark.parametrize("kind", ["admin", "customer", "legacy_admin"])
def test_record_limit_counts_all_pages_and_allows_edit_and_delete(console, kind):
    app, client, requests, records = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    if kind == "customer":
        assert assign(client, headers, app.state.store.user_by_name("customer")["id"], [ZONE]).status_code == 200
        headers = login(client, "customer")
    fill_records(records, 100)
    prefix = "/api/admin/cloudflare" if kind == "legacy_admin" else "/api/dns"
    endpoint = f"{prefix}/zones/{ZONE}/records"
    requests.clear()
    response = client.post(endpoint, headers=headers, json={"type": "A", "name": "aaa", "content": "192.0.2.1"})
    assert response.status_code == 409 and "100" in response.text
    assert len(records) == 100 and all(request.method == "GET" for request in requests)
    count_requests = [request for request in requests if request.url.path.endswith("/dns_records")]
    assert [request.url.params["page"] for request in count_requests] == ["1", "2"]
    assert client.put(endpoint + "/" + RECORD, headers=headers, json={"type": "TXT", "name": "@", "content": "updated"}).status_code == 200
    assert client.delete(endpoint + "/" + RECORD, headers=headers).status_code == 200
    assert client.post(endpoint, headers=headers, json={"type": "A", "name": "aaa", "content": "192.0.2.1"}).status_code == 201
    assert len(records) == 100


@pytest.mark.parametrize("console", [{"delay": True}], indirect=True)
def test_concurrent_creates_at_99_records_cannot_exceed_100(console):
    _, client, requests, records = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    fill_records(records, 99)
    endpoint = f"/api/dns/zones/{ZONE}/records"
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(client.post, endpoint, headers=headers,
                                   json={"type": "A", "name": name, "content": "192.0.2.1"}) for name in ("first", "second")]
        responses = [future.result(timeout=10) for future in futures]
    assert sorted(response.status_code for response in responses) == [201, 409]
    assert len(records) == 100
    assert len([request for request in requests if request.method == "POST"]) == 1


@pytest.mark.parametrize("console", [{"delay": True}], indirect=True)
def test_two_customers_share_the_same_zone_quota_and_lock(console):
    app, client, requests, records = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    for username in ("customer", "bob"):
        assert assign(client, headers, app.state.store.user_by_name(username)["id"], [ZONE]).status_code == 200
    first_headers = login(client, "customer")
    fill_records(records, 99)
    endpoint = f"/api/dns/zones/{ZONE}/records"
    with TestClient(app) as second_client:
        second_headers = login(second_client, "bob")
        with ThreadPoolExecutor(max_workers=2) as executor:
            calls = [executor.submit(http_client.post, endpoint, headers=auth,
                                     json={"type": "A", "name": name, "content": "192.0.2.1"})
                     for http_client, auth, name in ((client, first_headers, "alice"), (second_client, second_headers, "bob"))]
            responses = [future.result(timeout=10) for future in calls]
    assert sorted(response.status_code for response in responses) == [201, 409]
    assert len(records) == 100
    assert len([request for request in requests if request.method == "POST"]) == 1


def test_customer_writes_still_require_csrf_and_permission_is_checked_after_waiting(console, monkeypatch):
    app, client, requests, _ = console
    headers = login(client)
    assert configure(client, headers).status_code == 200
    customer = app.state.store.user_by_name("customer")
    assert assign(client, headers, customer["id"], [ZONE]).status_code == 200
    headers = login(client, "customer")
    endpoint = f"/api/dns/zones/{ZONE}/records"
    requests.clear()
    assert client.post(endpoint, json={"type": "A", "name": "www", "content": "192.0.2.1"}).status_code == 403
    assert client.delete(endpoint + "/" + RECORD).status_code == 403
    assert requests == []
    original = cloudflare.CloudflareClient.list_records
    async def revoke_during_read(cf_client, zone_id):
        value = await original(cf_client, zone_id)
        app.state.store.set_user_domains(customer["id"], ACCOUNT, [])
        return value
    monkeypatch.setattr(cloudflare.CloudflareClient, "list_records", revoke_during_read)
    response = client.post(endpoint, headers=headers, json={"type": "A", "name": "www", "content": "192.0.2.1"})
    assert response.status_code == 403
    assert all(request.method == "GET" for request in requests)

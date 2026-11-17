"""Snapshot validation and SSH orchestration tests; no real SSH connections."""

import asyncio
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import sqlite3
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.migration import (
    BACKUP_ROOT,
    MAX_DATABASE_BYTES,
    MigrationError,
    _BACKUP_SCRIPT,
    _COMMIT_IMPORT_SCRIPT,
    _PREPARE_IMPORT_SCRIPT,
    _ROLLBACK_SCRIPT,
    backup_remote,
    import_remote_database,
    normalize_panel_path,
    rollback_remote,
    validate_database,
)


def make_db(path: Path, version="2.9.4") -> Path:
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
            CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT);
            CREATE TABLE inbounds (id INTEGER PRIMARY KEY, settings TEXT, stream_settings TEXT, port INTEGER);
            INSERT INTO users VALUES (1, 'old-admin', 'old-password-hash');
        """)
        db.execute("INSERT INTO inbounds (id,settings,stream_settings,port) VALUES (1, ?, ?, 10001)", (
            json.dumps({"clients": [{"email": "one"}, {"email": "two"}]}),
            json.dumps({"tlsSettings": {"certificates": [{"certificateFile": "/old/fullchain.pem", "keyFile": "/old/key.pem"}]}}),
        ))
        db.executemany("INSERT INTO settings (key,value) VALUES (?,?)", [
            ("twoFactorEnable", "true"),
            ("twoFactorToken", "original-private-otp-secret"),
            ("webPort", "8443"),
            ("webBasePath", "/legacy/"),
            ("webCertFile", "/old/fullchain.pem"),
            ("subDomain", "old.example.com"),
        ])
        if version == "3.4.2":
            db.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT)")
            db.executemany("INSERT INTO clients (email) VALUES (?)", [("one",), ("two",), ("three",)])
    db.close()
    return path


def test_snapshot_statistics_and_warnings_without_modification(tmp_path):
    path = make_db(tmp_path / "upload.db")
    original = path.read_bytes()
    original_files = set(tmp_path.iterdir())
    result = validate_database(path, "v2.9.4", "2.9.4")
    assert result["inbounds"] == 1
    assert result["clients"] == 2
    assert result["two_factor_enabled"] is True
    assert result["panel_settings"] == {"port": 8443, "path": "/legacy/"}
    assert result["inbound_ports"] == [10001]
    assert result["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["external_dependencies"] == ["/old/fullchain.pem", "/old/key.pem"]
    assert any("二次验证" in warning for warning in result["warnings"])
    assert any("订阅" in warning for warning in result["warnings"])
    assert path.read_bytes() == original
    assert set(tmp_path.iterdir()) == original_files
    serialized = json.dumps(result)
    assert "old-admin" not in serialized
    assert "old-password-hash" not in serialized
    assert "original-private-otp-secret" not in serialized


@pytest.mark.parametrize("version", ["2.9.4", "3.4.2"])
def test_missing_panel_settings_use_verified_official_defaults_without_writing(tmp_path, version):
    path = make_db(tmp_path / "defaults.db", version)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM settings WHERE key IN ('webPort','webBasePath')")
    db.close()
    original, original_files = path.read_bytes(), set(tmp_path.iterdir())
    result = validate_database(path, version, version)
    assert result["panel_settings"] == {"port": 2053, "path": "/"}
    assert any("默认端口 2053" in warning for warning in result["warnings"])
    assert any("默认路径 /" in warning for warning in result["warnings"])
    assert path.read_bytes() == original
    assert set(tmp_path.iterdir()) == original_files


@pytest.mark.parametrize("value,expected", [
    ("/", "/"), ("", "/"), ("old", "/old/"), ("/a/", "/a/"),
    ("/old/admin.v2_~-/", "/old/admin.v2_~-/"), ("/面板/", "/面板/"),
])
def test_original_base_path_normalization(value, expected):
    assert normalize_panel_path(value) == expected


@pytest.mark.parametrize("value", [
    "https://evil.example/", "//evil.example/", "/old//admin/", "/old/../admin/",
    "/./", "/%2e%2e/", "/old?next=evil", "/old#fragment", "/old\\admin/",
    "/old\n/", "/old\x00/", "/old;reboot/", "/$(id)/", "/a b/", None,
])
def test_unsafe_original_base_path_is_rejected(value):
    with pytest.raises(MigrationError, match="入口路径"):
        normalize_panel_path(value)


@pytest.mark.parametrize("value,expected", [("old/admin.v2", "/old/admin.v2/"), ("/", "/")])
def test_original_database_path_is_extracted_without_modification(tmp_path, value, expected):
    path = make_db(tmp_path / "original-path.db")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE settings SET value=? WHERE key='webBasePath'", (value,))
    db.close()
    original, original_files = path.read_bytes(), set(tmp_path.iterdir())
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["panel_settings"]["path"] == expected
    assert path.read_bytes() == original
    assert set(tmp_path.iterdir()) == original_files


def test_unsafe_database_path_is_rejected_without_modification(tmp_path):
    path = make_db(tmp_path / "unsafe-path.db")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE settings SET value='/old?next=https://evil.example/' WHERE key='webBasePath'")
    db.close()
    original, original_files = path.read_bytes(), set(tmp_path.iterdir())
    with pytest.raises(MigrationError, match="入口路径"):
        validate_database(path, "2.9.4", "2.9.4")
    assert path.read_bytes() == original
    assert set(tmp_path.iterdir()) == original_files


@pytest.mark.parametrize("value", ["0", "65536", "-1", "22.5", "bad", " 2053", None])
def test_invalid_original_panel_port_rejected(tmp_path, value):
    path = make_db(tmp_path / "port.db")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE settings SET value=? WHERE key='webPort'", (value,))
    db.close()
    with pytest.raises(MigrationError, match="webPort"):
        validate_database(path, "2.9.4", "2.9.4")


def test_empty_v2_port_is_invalid_but_v3_uses_its_official_effective_default(tmp_path):
    for version in ("2.9.4", "3.4.2"):
        path = make_db(tmp_path / f"empty-{version}.db", version)
        with sqlite3.connect(path) as db:
            db.execute("UPDATE settings SET value='' WHERE key='webPort'")
        db.close()
        if version == "2.9.4":
            with pytest.raises(MigrationError, match="webPort"):
                validate_database(path, version, version)
        else:
            assert validate_database(path, version, version)["panel_settings"]["port"] == 2053


@pytest.mark.parametrize("value", ["1", "22", "80", "65535"])
def test_valid_port_range_is_extracted_for_callers_to_check_conflicts(tmp_path, value):
    path = make_db(tmp_path / "valid-port.db")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE settings SET value=? WHERE key='webPort'", (value,))
    db.close()
    assert validate_database(path, "2.9.4", "2.9.4")["panel_settings"]["port"] == int(value)


@pytest.mark.parametrize("key,value", [("webPort", "9443"), ("webBasePath", "/different/")])
def test_duplicate_panel_settings_are_ambiguous_and_rejected(tmp_path, key, value):
    path = make_db(tmp_path / "duplicate.db")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO settings (key,value) VALUES (?,?)", (key, value))
    db.close()
    with pytest.raises(MigrationError, match="设置重复"):
        validate_database(path, "2.9.4", "2.9.4")


def test_inbound_ports_are_sorted_deduplicated_and_not_sensitive(tmp_path):
    path = make_db(tmp_path / "inbound-ports.db")
    with sqlite3.connect(path) as db:
        db.executemany("INSERT INTO inbounds (id,settings,stream_settings,port) VALUES (?, '{}','{}',?)", [
            (2, 443), (3, 10001), (4, 80),
        ])
        db.execute("INSERT INTO users VALUES (2,'second-admin','private-password-hash')")
    db.close()
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["inbound_ports"] == [80, 443, 10001]
    assert any("全部保留原账号和密码" in warning for warning in result["warnings"])
    assert "private-password-hash" not in json.dumps(result)


def test_invalid_inbound_port_cannot_be_used_for_port_planning(tmp_path):
    path = make_db(tmp_path / "bad-inbound-port.db")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE inbounds SET port=70000")
    db.close()
    with pytest.raises(MigrationError, match="入站端口"):
        validate_database(path, "2.9.4", "2.9.4")


def test_v3_uses_clients_table_for_count(tmp_path):
    path = make_db(tmp_path / "upload.db", "3.4.2")
    assert validate_database(path, "3.4.2", "3.4.2")["clients"] == 3


@pytest.mark.parametrize("source,target", [("2.9.4", "3.4.2"), ("3.4.2", "2.9.4")])
def test_cross_version_is_rejected_before_accessing_file(tmp_path, source, target):
    with pytest.raises(MigrationError, match="同版本"):
        validate_database(tmp_path / "missing.db", source, target)


def test_declared_version_cannot_silently_downgrade_v3_database(tmp_path):
    path = make_db(tmp_path / "v3.db", "3.4.2")
    before = path.read_bytes()
    with pytest.raises(MigrationError, match="客户数据遗漏") as caught:
        validate_database(path, "2.9.4", "2.9.4")
    message = str(caught.value)
    assert "2.9.4 → 2.9.4" in message and "clients 有 3 条记录" in message
    assert "精确版本" in message and "不要自行删除" in message
    assert not any(value in message for value in ("old-admin", "old-password-hash", "original-private-otp-secret"))
    assert path.read_bytes() == before


@pytest.mark.parametrize("tables", [("clients",), ("client_inbounds",), ("clients", "client_inbounds")])
def test_v2_accepts_empty_residual_client_tables_without_modifying_snapshot(tmp_path, tables):
    path = make_db(tmp_path / "residual.db")
    with sqlite3.connect(path) as db:
        if "clients" in tables:
            db.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT)")
        if "client_inbounds" in tables:
            db.execute("CREATE TABLE client_inbounds (client_id INTEGER, inbound_id INTEGER)")
    before, files = path.read_bytes(), set(tmp_path.iterdir())
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["clients"] == 2 and result["client_count_kind"] == "入站客户条目"
    assert result["panel_settings"] == {"port": 8443, "path": "/legacy/"}
    assert any("历史版本遗留" in message for message in result["warnings"])
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == files


@pytest.mark.parametrize("has_clients_table", [False, True])
def test_v2_rejects_nonempty_client_links_even_if_clients_missing_or_empty(tmp_path, has_clients_table):
    path = make_db(tmp_path / "orphan-links.db")
    with sqlite3.connect(path) as db:
        if has_clients_table:
            db.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT)")
        db.execute("CREATE TABLE client_inbounds (client_id INTEGER, inbound_id INTEGER)")
        db.execute("INSERT INTO client_inbounds VALUES (1,1)")
    with pytest.raises(MigrationError, match="client_inbounds 有 1 条关联"):
        validate_database(path, "2.9.4", "2.9.4")


@pytest.mark.parametrize("table", ["Clients", "Client_Inbounds"])
def test_nonempty_residual_table_detection_matches_sqlite_identifier_case_rules(tmp_path, table):
    path = make_db(tmp_path / "mixed-case.db")
    with sqlite3.connect(path) as db:
        db.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
        db.execute(f"INSERT INTO {table} VALUES (1)")
    with pytest.raises(MigrationError, match="客户数据遗漏"):
        validate_database(path, "2.9.4", "2.9.4")


def add_deleted_inbound_clients(path: Path) -> None:
    """Synthetic history separate from the two current inbound JSON clients."""
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE clients (id INTEGER, email TEXT, uuid TEXT, sub_id TEXT,
                                  password TEXT, auth TEXT);
            CREATE TABLE client_inbounds (client_id INTEGER, inbound_id INTEGER);
            INSERT INTO clients VALUES
                (101, 'history-one', 'history-uuid-one', 'history-sub-one', '', ''),
                (102, 'history-two', 'history-uuid-two', 'history-sub-two', '', '');
            INSERT INTO client_inbounds VALUES (101,201), (102,202);
        """)
        db.execute("UPDATE inbounds SET settings=?", (json.dumps({"clients": [
            {"email": "one", "id": "current-uuid-one", "subId": "current-sub-one",
             "password": "current-password-one", "auth": "current-auth-one"},
            {"email": "two", "id": "current-uuid-two", "subId": "current-sub-two"},
        ]}),))


@pytest.mark.parametrize("mixed_case", [False, True])
def test_v2_accepts_only_deleted_inbound_history_and_keeps_every_table_byte_for_byte(tmp_path, mixed_case):
    path = make_db(tmp_path / "deleted-inbound-history.db")
    add_deleted_inbound_clients(path)
    if mixed_case:
        with sqlite3.connect(path) as db:
            db.execute("ALTER TABLE clients RENAME TO mixed_clients")
            db.execute("ALTER TABLE mixed_clients RENAME TO Clients")
            db.execute("ALTER TABLE client_inbounds RENAME TO mixed_links")
            db.execute("ALTER TABLE mixed_links RENAME TO Client_Inbounds")
    before, files = path.read_bytes(), set(tmp_path.iterdir())
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["clients"] == 2 and result["inbounds"] == 1
    assert result["client_count_kind"] == "入站客户条目"
    assert result["panel_settings"] == {"port": 8443, "path": "/legacy/"}
    assert any("已删除入站" in warning and "原样保留" in warning for warning in result["warnings"])
    assert not any(phrase in warning for warning in result["warnings"] for phrase in ("请管理员", "联系管理员", "等待管理员"))
    assert result["sha256"] == hashlib.sha256(before).hexdigest()
    serialized = json.dumps(result)
    for secret in ("history-one", "history-uuid-one", "history-sub-one", "current-uuid-one",
                   "current-password-one", "current-auth-one", "old-password-hash"):
        assert secret not in serialized
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == files


def test_v2_accepts_multiple_deleted_inbound_links_per_historical_client(tmp_path):
    path = make_db(tmp_path / "multiple-deleted-links.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO client_inbounds VALUES (101,203)")
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["clients"] == 2
    assert any("已删除入站" in warning for warning in result["warnings"])


def test_v2_current_fourteen_clients_with_nine_deleted_inbound_records_counts_only_current_json(tmp_path):
    path = make_db(tmp_path / "synthetic-fourteen-current-nine-history.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM inbounds")
        db.execute("DELETE FROM clients")
        db.execute("DELETE FROM client_inbounds")
        db.executemany("INSERT INTO inbounds(id,settings,stream_settings,port) VALUES(?,?,?,?)", [
            (index, json.dumps({"clients": [{"email": f"synthetic-current-{index}", "id": f"synthetic-current-id-{index}"}]}),
             "{}", 10000 + index) for index in range(1, 15)
        ])
        db.executemany("INSERT INTO clients VALUES(?,?,?,?,?,?)", [
            (index, f"synthetic-history-{index}", f"synthetic-history-id-{index}", "", "", "")
            for index in range(101, 110)
        ])
        db.executemany("INSERT INTO client_inbounds VALUES(?,?)", [(index, index + 100) for index in range(101, 110)])
    before = path.read_bytes()
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["inbounds"] == 14 and result["clients"] == 14
    assert any("9" in warning and "已删除入站" in warning for warning in result["warnings"])
    assert path.read_bytes() == before


def test_v2_deleted_inbound_history_allows_absent_optional_credential_columns(tmp_path):
    path = make_db(tmp_path / "minimal-deleted-history.db")
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT);
            CREATE TABLE client_inbounds (client_id INTEGER, inbound_id INTEGER);
            INSERT INTO clients VALUES (101,'history-only');
            INSERT INTO client_inbounds VALUES (101,201);
        """)
    assert validate_database(path, "2.9.4", "2.9.4")["clients"] == 2


@pytest.mark.parametrize("mutation", [
    "DELETE FROM client_inbounds WHERE client_id=101",
    "DROP TABLE client_inbounds",
    "DELETE FROM clients WHERE id=101",
    "UPDATE client_inbounds SET inbound_id=1 WHERE client_id=101",
    "INSERT INTO client_inbounds VALUES(101,1)",
    "UPDATE clients SET id=NULL WHERE id=101",
    "UPDATE clients SET id=0 WHERE id=101",
    "UPDATE clients SET id=-101 WHERE id=101",
    "UPDATE clients SET id=101.5 WHERE id=101",
    "UPDATE clients SET id='not-an-id' WHERE id=101",
    "UPDATE clients SET id=102 WHERE id=101",
    "UPDATE client_inbounds SET client_id=NULL WHERE client_id=101",
    "UPDATE client_inbounds SET inbound_id=NULL WHERE client_id=101",
    "UPDATE client_inbounds SET inbound_id=0 WHERE client_id=101",
    "UPDATE client_inbounds SET inbound_id=-201 WHERE client_id=101",
    "INSERT INTO client_inbounds VALUES(101,201)",
    "UPDATE clients SET email='' WHERE id=101",
    "UPDATE clients SET email='   ' WHERE id=101",
    "UPDATE clients SET email=NULL WHERE id=101",
    "UPDATE clients SET email=x'0102' WHERE id=101",
    "ALTER TABLE clients RENAME COLUMN email TO unsupported_email",
    "ALTER TABLE client_inbounds RENAME COLUMN inbound_id TO unsupported_inbound",
])
def test_v2_ambiguous_or_live_independent_history_still_fails_without_mutation(tmp_path, mutation):
    path = make_db(tmp_path / "unsafe-history.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        db.execute(mutation)
    before, files = path.read_bytes(), set(tmp_path.iterdir())
    with pytest.raises(MigrationError, match="客户数据遗漏") as caught:
        validate_database(path, "2.9.4", "2.9.4")
    message = str(caught.value)
    assert "管理员" not in message
    assert "history-one" not in message and "history-uuid-one" not in message
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == files


@pytest.mark.parametrize("column,current_key", [
    ("email", "email"), ("uuid", "id"), ("sub_id", "subId"),
    ("password", "password"), ("auth", "auth"),
])
@pytest.mark.parametrize("case_variant", [False, True])
def test_v2_deleted_history_identity_collision_cannot_hide_current_customer_conflicts(tmp_path, column, current_key, case_variant):
    path = make_db(tmp_path / "conflicting-history.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        current = json.loads(db.execute("SELECT settings FROM inbounds WHERE id=1").fetchone()[0])["clients"][0]
        value = current[current_key].upper() if case_variant else current[current_key]
        db.execute(f"UPDATE clients SET {column}=? WHERE id=101", (value,))
    before = path.read_bytes()
    with pytest.raises(MigrationError, match="客户数据遗漏") as caught:
        validate_database(path, "2.9.4", "2.9.4")
    assert value not in str(caught.value)
    assert path.read_bytes() == before


@pytest.mark.parametrize("payload", [
    [], ["not-a-client"], {"clients": None}, {"clients": {}},
    {"clients": ["not-a-client"]}, {"clients": [None]},
])
def test_v2_deleted_history_does_not_bypass_invalid_current_json_clients(tmp_path, payload):
    path = make_db(tmp_path / "bad-current-clients.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE inbounds SET settings=?", (json.dumps(payload),))
    before = path.read_bytes()
    with pytest.raises(MigrationError, match="JSON"):
        validate_database(path, "2.9.4", "2.9.4")
    assert path.read_bytes() == before


@pytest.mark.parametrize("field", ["email", "id", "subId", "password", "auth"])
def test_v2_deleted_history_requires_current_identity_values_to_have_valid_types(tmp_path, field):
    path = make_db(tmp_path / "bad-current-identity.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE inbounds SET settings=?", (json.dumps({"clients": [{field: 123}]}),))
    with pytest.raises(MigrationError, match="客户数据遗漏"):
        validate_database(path, "2.9.4", "2.9.4")


@pytest.mark.parametrize("populated", [False, True])
def test_v2_historical_api_tokens_are_preserved_with_notice_without_returning_token_values(tmp_path, populated):
    path = make_db(tmp_path / "historical-api-tokens.db")
    add_deleted_inbound_clients(path)
    token = "test-only-private-historical-api-token"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE api_tokens(id INTEGER PRIMARY KEY, token TEXT)")
        if populated:
            db.execute("INSERT INTO api_tokens VALUES(1,?)", (token,))
    before, files = path.read_bytes(), set(tmp_path.iterdir())
    result = validate_database(path, "2.9.4", "2.9.4")
    notices = [warning for warning in result["warnings"] if "API 令牌" in warning]
    assert bool(notices) == populated
    if populated:
        assert all("原样保留" in warning and "2.9.4 不读取" in warning for warning in notices)
    assert token not in json.dumps(result)
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == files


@pytest.mark.parametrize("node_id", [None, 0])
def test_v2_deleted_inbound_history_accepts_only_local_or_unset_node_ownership(tmp_path, node_id):
    path = make_db(tmp_path / "local-node-history.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        # No affinity: the checker must distinguish SQLite integers from text
        # and real values, rather than relying on coercion by an INTEGER column.
        db.execute("ALTER TABLE inbounds ADD COLUMN node_id")
        db.execute("UPDATE inbounds SET node_id=?", (node_id,))
    before = path.read_bytes()
    result = validate_database(path, "2.9.4", "2.9.4")
    assert result["clients"] == 2
    assert path.read_bytes() == before


@pytest.mark.parametrize("node_id", [1, -1, 0.0, 1.5, "0", "remote-node", b"\x00"])
def test_v2_deleted_inbound_history_cannot_restore_remote_or_ambiguous_nodes_as_local(tmp_path, node_id):
    path = make_db(tmp_path / "remote-node-history.db")
    add_deleted_inbound_clients(path)
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE inbounds ADD COLUMN node_id")
        db.execute("UPDATE inbounds SET node_id=?", (node_id,))
    before, files = path.read_bytes(), set(tmp_path.iterdir())
    with pytest.raises(MigrationError, match="远程节点归属"):
        validate_database(path, "2.9.4", "2.9.4")
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == files


def test_v2_historical_node_guard_does_not_reject_v3_node_assignments(tmp_path):
    path = make_db(tmp_path / "v3-nodes.db", "3.4.2")
    with sqlite3.connect(path) as db:
        db.execute("ALTER TABLE inbounds ADD COLUMN node_id")
        db.execute("UPDATE inbounds SET node_id=7")
    before = path.read_bytes()
    assert validate_database(path, "3.4.2", "3.4.2")["clients"] == 3
    assert path.read_bytes() == before


def test_declared_v3_requires_clients_table(tmp_path):
    with pytest.raises(MigrationError, match="clients"):
        validate_database(make_db(tmp_path / "v2.db"), "3.4.2", "3.4.2")


def test_renamed_non_sqlite_file_rejected(tmp_path):
    path = tmp_path / "x-ui.db"
    path.write_text("not a database")
    with pytest.raises(MigrationError, match="不是 SQLite"):
        validate_database(path, "2.9.4", "2.9.4")


def test_size_limit_before_sqlite_open(tmp_path):
    path = tmp_path / "large.db"
    with path.open("wb") as stream:
        stream.truncate(MAX_DATABASE_BYTES + 1)
    with pytest.raises(MigrationError, match="50 MiB"):
        validate_database(path, "2.9.4", "2.9.4")


def test_arbitrary_sqlite_database_is_not_accepted(tmp_path):
    path = tmp_path / "other.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE test (value TEXT)")
    with pytest.raises(MigrationError, match="必需"):
        validate_database(path, "2.9.4", "2.9.4")


def test_corrupted_sqlite_header_rejected(tmp_path):
    path = make_db(tmp_path / "broken.db")
    with path.open("r+b") as stream:
        stream.seek(100)
        stream.write(b"\xff" * 64)
    with pytest.raises(MigrationError):
        validate_database(path, "2.9.4", "2.9.4")


def test_custom_triggers_rejected_without_firing(tmp_path):
    path = make_db(tmp_path / "trigger.db")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TRIGGER malicious AFTER UPDATE ON users BEGIN DELETE FROM inbounds; END")
    with pytest.raises(MigrationError, match="触发器"):
        validate_database(path, "2.9.4", "2.9.4")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM inbounds").fetchone()[0] == 1


def test_invalid_inbound_json_does_not_pass_as_success(tmp_path):
    path = make_db(tmp_path / "bad-json.db")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE inbounds SET settings='not-json'")
    with pytest.raises(MigrationError, match="JSON"):
        validate_database(path, "2.9.4", "2.9.4")


class FakeSFTP:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def put(self, source, target):
        self.connection.events.append(("upload", source, target))


class FakeConnection:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.events = []

    async def run(self, command, **kwargs):
        assert kwargs["check"] is True
        assert kwargs["timeout"] > 0
        self.events.append(("run", command, kwargs["input"]))
        response = next(self.responses)
        if isinstance(response, BaseException):
            raise response
        return SimpleNamespace(stdout=json.dumps(response))

    def start_sftp_client(self):
        return FakeSFTP(self)


def test_remote_backup_returns_persistent_directory():
    conn = FakeConnection([{"backup_path": BACKUP_ROOT + "/job-123"}])
    assert asyncio.run(backup_remote(conn, "job-123")) == BACKUP_ROOT + "/job-123"
    assert conn.events[0][1] == "python3 - job-123"


def test_remote_backup_passes_only_validated_target_certificate_domain():
    conn = FakeConnection([{"backup_path": BACKUP_ROOT + "/job-123"}])
    assert asyncio.run(backup_remote(conn, "job-123", cert_domain="panel.example.com")) == BACKUP_ROOT + "/job-123"
    assert conn.events[0][1] == "python3 - job-123 panel.example.com"


@pytest.mark.parametrize("domain", ["", "../cert", "/root/cert", "example.com/../other", "*.example.com",
                                       "example.com;reboot", "example.com\n", "example.com\\other", ".", "a" * 64 + ".com"])
def test_invalid_certificate_domain_never_reaches_ssh(domain):
    conn = FakeConnection([])
    with pytest.raises(MigrationError, match="证书域名"):
        asyncio.run(backup_remote(conn, "job-123", cert_domain=domain))
    assert conn.events == []


def test_upload_is_staged_and_committed_after_sftp(tmp_path):
    path = make_db(tmp_path / "snapshot.db")
    conn = FakeConnection([
        {"temporary_path": "/etc/x-ui/.x-ui-upload-job-123.db"},
        {"database_path": "/etc/x-ui/x-ui.db", "has_two_factor": True},
    ])
    result = asyncio.run(import_remote_database(conn, path, BACKUP_ROOT + "/job-123", "job-123"))
    assert [event[0] for event in conn.events] == ["run", "upload", "run"]
    assert conn.events[1][2] == "/etc/x-ui/.x-ui-upload-job-123.db"
    assert hashlib.sha256(path.read_bytes()).hexdigest() in conn.events[2][1]
    assert result["has_two_factor"] is True


def test_invalid_remote_upload_path_is_never_followed(tmp_path):
    path = make_db(tmp_path / "snapshot.db")
    conn = FakeConnection([{"temporary_path": "/root/.ssh/authorized_keys"}])
    with pytest.raises(MigrationError, match="上传路径"):
        asyncio.run(import_remote_database(conn, path, BACKUP_ROOT + "/job-123", "job-123"))
    assert not any(event[0] == "upload" for event in conn.events)


def test_remote_commit_failure_propagates_for_caller_rollback(tmp_path):
    path = make_db(tmp_path / "snapshot.db")
    conn = FakeConnection([
        {"temporary_path": "/etc/x-ui/.x-ui-upload-job-123.db"},
        RuntimeError("checksum mismatch"),
    ])
    with pytest.raises(RuntimeError, match="checksum"):
        asyncio.run(import_remote_database(conn, path, BACKUP_ROOT + "/job-123", "job-123"))


@pytest.mark.parametrize("identifier", ["../../etc", "job;reboot", "$(id)", "", "a" * 81])
def test_invalid_job_identifier_never_reaches_ssh(identifier):
    conn = FakeConnection([])
    with pytest.raises(MigrationError):
        asyncio.run(backup_remote(conn, identifier))
    assert conn.events == []


def test_backup_for_other_job_is_rejected_before_ssh(tmp_path):
    conn = FakeConnection([])
    with pytest.raises(MigrationError, match="不匹配"):
        asyncio.run(import_remote_database(conn, tmp_path / "unused.db", BACKUP_ROOT + "/other", "job-123"))
    assert conn.events == []


def test_rollback_path_cannot_target_arbitrary_server_directories():
    conn = FakeConnection([])
    with pytest.raises(MigrationError):
        asyncio.run(rollback_remote(conn, "/etc/x-ui"))
    assert conn.events == []


@pytest.mark.parametrize("script", [_BACKUP_SCRIPT, _PREPARE_IMPORT_SCRIPT, _COMMIT_IMPORT_SCRIPT, _ROLLBACK_SCRIPT])
def test_remote_python_scripts_compile(script):
    compile(script, "remote-migration-helper", "exec")


def _sandbox_path(value, sandbox_root, path_type=Path):
    """Map remote paths once, including on hosts with POSIX temporary paths."""
    root, candidate = path_type(sandbox_root), path_type(value)
    # os.walk and script arguments can already contain a mapped absolute path.
    # Check path components rather than string prefixes (sandbox vs sandbox2).
    if candidate.is_relative_to(root):
        return candidate
    text = str(value)
    return root / text.lstrip("/") if text.startswith("/") else candidate


@pytest.mark.parametrize("path_type,sandbox_root", [
    (PurePosixPath, "/tmp/migration-sandbox"),
    (PureWindowsPath, "C:/temp/migration-sandbox"),
])
def test_script_sandbox_maps_remote_paths_once_and_preserves_local_backup_arguments(path_type, sandbox_root):
    root = path_type(sandbox_root)
    for remote_path in ("/usr/local/x-ui/x-ui", BACKUP_ROOT + "/snapshot-job"):
        mapped = _sandbox_path(remote_path, root, path_type)
        assert mapped == root / remote_path.lstrip("/")
        assert _sandbox_path(mapped, root, path_type) == mapped
        assert _sandbox_path(str(mapped), root, path_type) == mapped
    # A neighboring directory is outside the sandbox despite its shared prefix.
    sibling = root.with_name(root.name + "2") / "etc/x-ui"
    assert not sibling.is_relative_to(root)
    if path_type is PurePosixPath:
        assert _sandbox_path(sibling, root, path_type) == root / str(sibling).lstrip("/")
    else:
        assert _sandbox_path(sibling, root, path_type) == sibling


@pytest.fixture
def remote_script_sandbox(tmp_path, monkeypatch):
    """Run the production remote scripts locally without systemd or SSH."""

    def sandbox_path(value):
        return _sandbox_path(value, tmp_path)

    active = {"running": True}

    def fake_systemctl(command, **kwargs):
        assert command[0] == "systemctl"
        arguments = command[1:]
        output, code = "", 0
        if arguments[0] == "is-active":
            code = 0 if active["running"] else 3
        elif arguments[0] == "is-enabled":
            output = "enabled\n"
        elif arguments[0] == "show":
            output = "loaded\n"
        elif arguments[0] == "stop":
            active["running"] = False
        elif arguments[0] == "start":
            active["running"] = True
        return SimpleNamespace(returncode=code, stdout=output, stderr="")

    def execute(script, *arguments):
        monkeypatch.setattr(sys, "argv", ["migration-helper", *arguments])
        exec(script.replace("from pathlib import Path", "Path = sandbox_path"), {"sandbox_path": sandbox_path})

    monkeypatch.setattr(subprocess, "run", fake_systemctl)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "chown", lambda *args, **kwargs: None, raising=False)
    return SimpleNamespace(path=sandbox_path, execute=execute, active=active)


def test_snapshot_includes_wal_and_rollback_restores_binary_and_database(remote_script_sandbox, capsys):
    """Run the real backup/restore scripts in a local sandbox, with no systemd."""
    sandbox_path, execute, active = remote_script_sandbox.path, remote_script_sandbox.execute, remote_script_sandbox.active
    binary = sandbox_path("/usr/local/x-ui/x-ui")
    binary.parent.mkdir(parents=True)
    binary.write_text("original-binary")
    original = sandbox_path("/etc/x-ui/x-ui.db")
    original.parent.mkdir(parents=True)
    make_db(original)
    live = sqlite3.connect(original)
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("INSERT INTO inbounds (id,settings,stream_settings) VALUES (2,'{}','{}')")
        live.commit()
        assert Path(str(original) + "-wal").exists()
        execute(_BACKUP_SCRIPT, "snapshot-job")
        capsys.readouterr()
        assert active["running"] is False
        backup = sandbox_path(BACKUP_ROOT + "/snapshot-job")
        saved = backup / "snapshot/etc/x-ui/x-ui.db"
        with sqlite3.connect(saved.resolve().as_uri() + "?mode=ro&immutable=1", uri=True) as db:
            assert db.execute("SELECT count(*) FROM inbounds").fetchone()[0] == 2
        db.close()
        assert not Path(str(saved) + "-wal").exists()
    finally:
        live.close()
    binary.write_text("new-installation-binary")
    with sqlite3.connect(original) as db:
        db.execute("DELETE FROM inbounds")
    db.close()
    execute(_ROLLBACK_SCRIPT, str(backup))
    capsys.readouterr()
    assert binary.read_text() == "original-binary"
    assert active["running"] is True
    with sqlite3.connect(original) as db:
        assert db.execute("SELECT count(*) FROM inbounds").fetchone()[0] == 2
    db.close()
    assert (backup / "manifest.json").exists()


def test_certificate_rollback_restores_existing_same_domain_and_preserves_other_domains(remote_script_sandbox):
    sandbox = remote_script_sandbox
    certificate = sandbox.path("/root/cert/panel.example.com")
    certificate.mkdir(parents=True, mode=0o700)
    (certificate / "fullchain.pem").write_text("original-fullchain")
    (certificate / "privkey.pem").write_text("original-private-key")
    (certificate / "privkey.pem").chmod(0o600)
    (certificate / "manual-note.txt").write_text("manual-certificate-note")
    other = sandbox.path("/root/cert/other.example.com")
    other.mkdir()
    (other / "privkey.pem").write_text("unrelated-private-key")
    sandbox.execute(_BACKUP_SCRIPT, "certificate-job", "panel.example.com")
    backup = sandbox.path(BACKUP_ROOT + "/certificate-job")
    manifest = json.loads((backup / "manifest.json").read_text())
    assert manifest["schema"] == 1 and manifest["cert_domain"] == "panel.example.com"
    assert manifest["entries"]["/root/cert/panel.example.com"]["exists"] is True
    assert "/root/cert/other.example.com" not in manifest["entries"]
    assert not (backup / "snapshot/root/cert/other.example.com").exists()
    (certificate / "fullchain.pem").write_text("task-fullchain")
    (certificate / "privkey.pem").write_text("task-private-key")
    (certificate / "manual-note.txt").unlink()
    (certificate / "task-extra.txt").write_text("task-created")
    sandbox.execute(_ROLLBACK_SCRIPT, str(backup))
    assert (certificate / "fullchain.pem").read_text() == "original-fullchain"
    assert (certificate / "privkey.pem").read_text() == "original-private-key"
    assert (certificate / "manual-note.txt").read_text() == "manual-certificate-note"
    assert not (certificate / "task-extra.txt").exists()
    assert (other / "privkey.pem").read_text() == "unrelated-private-key"
    assert not certificate.with_name(".panel.example.com.failed-certificate-job").exists()
    if os.name != "nt":
        assert stat.S_IMODE((certificate / "privkey.pem").stat().st_mode) == 0o600


def test_certificate_rollback_removes_only_new_target_domain_directory(remote_script_sandbox):
    sandbox = remote_script_sandbox
    other = sandbox.path("/root/cert/other.example.com")
    other.mkdir(parents=True)
    (other / "fullchain.pem").write_text("other-certificate")
    sandbox.execute(_BACKUP_SCRIPT, "new-certificate-job", "panel.example.com")
    backup = sandbox.path(BACKUP_ROOT + "/new-certificate-job")
    manifest = json.loads((backup / "manifest.json").read_text())
    assert manifest["entries"]["/root/cert/panel.example.com"] == {"exists": False}
    certificate = sandbox.path("/root/cert/panel.example.com")
    certificate.mkdir()
    (certificate / "fullchain.pem").write_text("new-task-certificate")
    (certificate / "privkey.pem").write_text("new-task-key")
    sandbox.execute(_ROLLBACK_SCRIPT, str(backup))
    assert not certificate.exists()
    assert not certificate.with_name(".panel.example.com.failed-new-certificate-job").exists()
    assert (other / "fullchain.pem").read_text() == "other-certificate"


def test_legacy_manifest_without_certificate_scope_still_rolls_back_and_never_touches_certificates(remote_script_sandbox):
    sandbox = remote_script_sandbox
    original = sandbox.path("/etc/x-ui/x-ui.db")
    original.parent.mkdir(parents=True)
    make_db(original)
    sandbox.execute(_BACKUP_SCRIPT, "legacy-job")
    backup = sandbox.path(BACKUP_ROOT + "/legacy-job")
    manifest = json.loads((backup / "manifest.json").read_text())
    assert "cert_domain" not in manifest
    certificate = sandbox.path("/root/cert/panel.example.com")
    certificate.mkdir(parents=True)
    (certificate / "privkey.pem").write_text("untouched-legacy-certificate")
    with sqlite3.connect(original) as db:
        db.execute("DELETE FROM users")
    db.close()
    sandbox.execute(_ROLLBACK_SCRIPT, str(backup))
    with sqlite3.connect(original) as db:
        assert db.execute("SELECT username FROM users").fetchone() == ("old-admin",)
    db.close()
    assert (certificate / "privkey.pem").read_text() == "untouched-legacy-certificate"


@pytest.mark.parametrize("blocked_path", ["/root", "/root/cert", "/root/cert/panel.example.com"])
def test_certificate_backup_rejects_symbolic_link_parents_or_domain_before_changes(remote_script_sandbox, monkeypatch, blocked_path):
    sandbox = remote_script_sandbox
    blocked = sandbox.path(blocked_path)
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == blocked or real_is_symlink(self))
    with pytest.raises(RuntimeError, match="Certificate"):
        sandbox.execute(_BACKUP_SCRIPT, "link-job", "panel.example.com")
    assert sandbox.active["running"] is True
    assert not sandbox.path(BACKUP_ROOT + "/link-job").exists()


def test_certificate_backup_rejects_nested_symbolic_link_without_following_it(remote_script_sandbox, monkeypatch):
    sandbox = remote_script_sandbox
    certificate = sandbox.path("/root/cert/panel.example.com")
    certificate.mkdir(parents=True)
    key = certificate / "privkey.pem"
    key.write_text("must-not-copy-or-overwrite")
    real_lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda self, *args, **kwargs:
                        SimpleNamespace(st_mode=stat.S_IFLNK | 0o777) if self == key else real_lstat(self, *args, **kwargs))
    with pytest.raises(RuntimeError, match="symbolic link"):
        sandbox.execute(_BACKUP_SCRIPT, "nested-link-job", "panel.example.com")
    assert key.read_text() == "must-not-copy-or-overwrite"
    assert not sandbox.path(BACKUP_ROOT + "/nested-link-job").exists()


def test_certificate_rollback_rejects_a_replaced_symlink_parent_before_restoring_any_files(remote_script_sandbox, monkeypatch):
    sandbox = remote_script_sandbox
    sandbox.execute(_BACKUP_SCRIPT, "changed-parent-job", "panel.example.com")
    backup = sandbox.path(BACKUP_ROOT + "/changed-parent-job")
    certificate_root = sandbox.path("/root/cert")
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == certificate_root or real_is_symlink(self))
    with pytest.raises(RuntimeError, match="Certificate parent"):
        sandbox.execute(_ROLLBACK_SCRIPT, str(backup))
    assert not sandbox.path("/etc/.x-ui.failed-changed-parent-job").exists()


@pytest.mark.parametrize("scope", ["target", "snapshot"])
def test_certificate_rollback_rejects_a_symbolic_link_directory_without_following_it(remote_script_sandbox, monkeypatch, scope):
    sandbox = remote_script_sandbox
    certificate = sandbox.path("/root/cert/panel.example.com")
    certificate.mkdir(parents=True)
    (certificate / "privkey.pem").write_text("original-key")
    sandbox.execute(_BACKUP_SCRIPT, "changed-link-job", "panel.example.com")
    backup = sandbox.path(BACKUP_ROOT + "/changed-link-job")
    blocked = certificate if scope == "target" else backup / "snapshot/root/cert/panel.example.com"
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == blocked or real_is_symlink(self))
    with pytest.raises(RuntimeError, match="Certificate directory"):
        sandbox.execute(_ROLLBACK_SCRIPT, str(backup))
    assert (certificate / "privkey.pem").read_text() == "original-key"
    assert not sandbox.path("/etc/.x-ui.failed-changed-link-job").exists()


def test_remote_certificate_domain_validation_rejects_manifest_path_traversal(remote_script_sandbox):
    sandbox = remote_script_sandbox
    with pytest.raises(RuntimeError, match="Invalid certificate domain"):
        sandbox.execute(_BACKUP_SCRIPT, "bad-domain-job", "../another-domain")
    assert not sandbox.path(BACKUP_ROOT + "/bad-domain-job").exists()

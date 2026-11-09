from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer',
                active INTEGER NOT NULL DEFAULT 1, session_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                kind TEXT NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL,
                server_ip TEXT NOT NULL, ssh_port INTEGER NOT NULL, ssh_username TEXT NOT NULL,
                domain TEXT NOT NULL, version TEXT NOT NULL, panel_port INTEGER NOT NULL,
                panel_path TEXT NOT NULL, source_version TEXT,
                overwrite_existing INTEGER NOT NULL, reset_two_factor INTEGER NOT NULL,
                encrypted_password TEXT, upload_path TEXT, validation TEXT,
                result TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_target ON tasks(server_ip)
                WHERE status IN ('queued','running');
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
                stage TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_by_task ON events(task_id,id);
            CREATE TABLE IF NOT EXISTS integrations (
                provider TEXT PRIMARY KEY, account_id TEXT NOT NULL,
                encrypted_token TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS domain_grants (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL, zone_id TEXT NOT NULL,
                zone_name TEXT NOT NULL,
                PRIMARY KEY(user_id,account_id,zone_id));
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
            if "session_version" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")
            task_columns = {row[1] for row in db.execute("PRAGMA table_info(tasks)")}
            if "custom_panel_port" not in task_columns:
                # Earlier versions required an explicit port for every task.
                db.execute("ALTER TABLE tasks ADD COLUMN custom_panel_port INTEGER NOT NULL DEFAULT 1")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def user(self, user_id: int) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            return dict(row) if row else None

    def user_by_name(self, username: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            return dict(row) if row else None

    def add_user(self, username: str, password_hash: str, role: str = "customer") -> dict:
        with self.connect() as db:
            cursor = db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (username, password_hash, role, now()))
            return {"id": cursor.lastrowid, "username": username, "role": role, "active": True}

    def users(self) -> list[dict]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,username,role,active,created_at FROM users ORDER BY id DESC")]

    def set_user_active(self, user_id: int, active: bool) -> bool:
        with self.connect() as db:
            cursor = db.execute("UPDATE users SET active=?,session_version=session_version+1 WHERE id=? AND role='customer' AND active != ?", (active, user_id, active))
            if not cursor.rowcount:
                return db.execute("SELECT 1 FROM users WHERE id=? AND role='customer'", (user_id,)).fetchone() is not None
            return cursor.rowcount == 1

    def integration(self, provider: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM integrations WHERE provider=?", (provider,)).fetchone()
            return dict(row) if row else None

    def save_integration(self, provider: str, account_id: str, encrypted_token: str) -> dict:
        with self.connect() as db:
            previous = db.execute("SELECT account_id FROM integrations WHERE provider=?", (provider,)).fetchone()
            if provider == "cloudflare" and previous and previous["account_id"] != account_id:
                # A replacement account requires an explicit new assignment.
                db.execute("DELETE FROM domain_grants")
            db.execute("""INSERT INTO integrations(provider,account_id,encrypted_token,updated_at)
                VALUES(?,?,?,?) ON CONFLICT(provider) DO UPDATE SET
                account_id=excluded.account_id,encrypted_token=excluded.encrypted_token,
                updated_at=excluded.updated_at""", (provider, account_id, encrypted_token, now()))
        return self.integration(provider)

    def user_domains(self, user_id: int, account_id: str) -> list[dict]:
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT zone_id AS id,zone_name AS name FROM domain_grants WHERE user_id=? AND account_id=? ORDER BY zone_name",
                (user_id, account_id))]

    def has_domain_access(self, user_id: int, account_id: str, zone_id: str) -> bool:
        with self.connect() as db:
            return db.execute("SELECT 1 FROM domain_grants WHERE user_id=? AND account_id=? AND zone_id=?",
                              (user_id, account_id, zone_id)).fetchone() is not None

    def set_user_domains(self, user_id: int, account_id: str, zones: list[dict]) -> None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            user = db.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
            if not user or user["role"] != "customer":
                raise ValueError("客户不存在，或该账号是管理员。")
            saved = db.execute("SELECT account_id FROM integrations WHERE provider='cloudflare'").fetchone()
            if not saved or saved["account_id"] != account_id:
                raise ValueError("Cloudflare 账户配置已变化，请刷新后重新分配域名。")
            db.execute("DELETE FROM domain_grants WHERE user_id=?", (user_id,))
            db.executemany("INSERT INTO domain_grants(user_id,account_id,zone_id,zone_name) VALUES(?,?,?,?)",
                           [(user_id, account_id, zone["id"], zone["name"]) for zone in zones])

    def create_task(self, values: dict[str, Any]) -> dict:
        values = {**values, "status": "queued", "stage": "queued", "created_at": now(), "updated_at": now()}
        columns = list(values)
        with self.connect() as db:
            db.execute(f"INSERT INTO tasks({','.join(columns)}) VALUES({','.join('?' for _ in columns)})", tuple(values.values()))
            db.execute("INSERT INTO events(task_id,stage,message,created_at) VALUES(?,?,?,?)", (values["id"], "queued", "任务已进入队列，等待服务器检查。", now()))
        return self.task(values["id"])

    @staticmethod
    def decode(row) -> dict | None:
        if row is None:
            return None
        value = dict(row)
        for key in ("result", "validation"):
            value[key] = json.loads(value[key]) if value[key] else None
        return value

    def task(self, task_id: str) -> dict | None:
        with self.connect() as db:
            return self.decode(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())

    def tasks(self, user_id: int | None) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM tasks WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT 200", (user_id,)) if user_id is not None else db.execute("SELECT * FROM tasks ORDER BY created_at DESC,rowid DESC LIMIT 200")
            return [self.decode(row) for row in rows]

    def events(self, task_id: str) -> list[dict]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM events WHERE task_id=? ORDER BY id LIMIT 2000", (task_id,))]

    def queue_snapshot(self) -> dict:
        with self.connect() as db:
            queued = db.execute("SELECT id FROM tasks WHERE status='queued' ORDER BY created_at,rowid").fetchall()
            running = db.execute("SELECT count(*) FROM tasks WHERE status='running'").fetchone()[0]
            return {"positions": {row["id"]: index + 1 for index, row in enumerate(queued)}, "running": running}

    def has_active_target(self, server_ip: str) -> bool:
        with self.connect() as db:
            return db.execute("SELECT 1 FROM tasks WHERE server_ip=? AND status IN ('queued','running')", (server_ip,)).fetchone() is not None

    def update_host_key(self, task_id: str, message: str, update: Callable[[], str | None]) -> str | None:
        # Keep queue submission/claim out until the scoped pin replacement and
        # its audit event complete. Recheck after the asynchronous key probe.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            task = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task or task["status"] not in {"failed", "interrupted"}:
                raise ValueError("任务状态已变化，请刷新后重新核实服务器指纹。")
            if db.execute("SELECT 1 FROM tasks WHERE server_ip=? AND status IN ('queued','running')", (task["server_ip"],)).fetchone():
                raise ValueError("该服务器还有等待或执行中的任务，本次未更新指纹。")
            warning = update()
            if warning:
                message += " " + warning
            db.execute("INSERT INTO events(task_id,stage,message,created_at) VALUES(?,?,?,?)", (task_id, task["stage"], message[:3000], now()))
            db.execute("UPDATE tasks SET updated_at=? WHERE id=?", (now(), task_id))
        return warning

    def event(self, task_id: str, stage: str, message: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO events(task_id,stage,message,created_at) VALUES(?,?,?,?)", (task_id, stage, message[:3000], now()))
            db.execute("UPDATE tasks SET stage=?,updated_at=? WHERE id=?", (stage, now(), task_id))

    def claim(self) -> dict | None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM tasks WHERE status='queued' ORDER BY created_at,rowid LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE tasks SET status='running',updated_at=? WHERE id=?", (now(), row["id"]))
            return self.decode(row)

    def finish(self, task_id: str, result: dict | None = None, error: str | None = None) -> None:
        with self.connect() as db:
            db.execute("UPDATE tasks SET status=?,stage=?,result=?,error=?,encrypted_password=NULL,updated_at=? WHERE id=?", ("failed" if error else "succeeded", "failed" if error else "completed", json.dumps(result, ensure_ascii=False) if result else None, error, now(), task_id))

    def interrupt_running(self) -> None:
        with self.connect() as db:
            rows = db.execute("SELECT id FROM tasks WHERE status='running'").fetchall()
            for row in rows:
                message = "网站执行进程曾中断。请检查目标服务器与备份后再重试；未自动重复执行安装或重启。"
                db.execute("UPDATE tasks SET status='interrupted',stage='interrupted',error=?,encrypted_password=NULL,updated_at=? WHERE id=?", (message, now(), row["id"]))
                db.execute("INSERT INTO events(task_id,stage,message,created_at) VALUES(?,?,?,?)", (row["id"], "interrupted", message, now()))

    def interrupt_task(self, task_id: str, message: str) -> None:
        with self.connect() as db:
            cursor = db.execute("UPDATE tasks SET status='interrupted',stage='interrupted',error=?,encrypted_password=NULL,updated_at=? WHERE id=? AND status='running'", (message, now(), task_id))
            if cursor.rowcount:
                db.execute("INSERT INTO events(task_id,stage,message,created_at) VALUES(?,?,?,?)", (task_id, "interrupted", message, now()))

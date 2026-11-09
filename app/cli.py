from __future__ import annotations

import argparse
import getpass
import sqlite3

from app.config import Settings
from app.db import Store
from app.security import hash_password, validate_username


def main() -> None:
    parser = argparse.ArgumentParser(description="网站管理员账号管理（密码通过交互输入，不进入命令行记录）。")
    parser.add_argument("action", choices=["create-admin", "reset-password"])
    parser.add_argument("username")
    args = parser.parse_args()
    settings = Settings.from_env()
    store = Store(settings.database)
    try:
        username = validate_username(args.username)
        password = getpass.getpass("网站密码（至少12位）: ")
        if password != getpass.getpass("再次输入: "):
            raise ValueError("两次密码不一致。")
        encoded = hash_password(password)
        if args.action == "create-admin":
            store.add_user(username, encoded, "admin")
        else:
            with store.connect() as db:
                cursor = db.execute("UPDATE users SET password_hash=?,session_version=session_version+1 WHERE username=?", (encoded, username))
                if not cursor.rowcount:
                    raise ValueError("账号不存在。")
        print("账号已更新。")
    except (ValueError, sqlite3.IntegrityError) as exc:
        parser.exit(1, f"操作失败：{exc}\n")


if __name__ == "__main__":
    main()

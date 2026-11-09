from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Settings:
    secret: str
    data_dir: Path
    cookie_secure: bool = True
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")
    enable_worker: bool = True
    allow_private_targets: bool = False
    max_concurrent_jobs: int = 2
    upload_retention_hours: int = 24

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        secret = os.getenv("APP_SECRET", "")
        if len(secret) < 32 or secret.startswith("REPLACE_"):
            raise RuntimeError("请设置 APP_SECRET：使用至少 32 位随机密钥，参考 .env.example。")
        return cls(
            secret=secret,
            data_dir=Path(os.getenv("DATA_DIR", "./data")).resolve(),
            cookie_secure=env_bool("COOKIE_SECURE", True),
            allowed_hosts=tuple(x.strip() for x in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if x.strip()),
            enable_worker=env_bool("ENABLE_WORKER", True),
            allow_private_targets=env_bool("ALLOW_PRIVATE_TARGETS", False),
            max_concurrent_jobs=max(1, min(8, int(os.getenv("MAX_CONCURRENT_JOBS", "2")))),
            upload_retention_hours=max(1, int(os.getenv("UPLOAD_RETENTION_HOURS", "24"))),
        )

    @property
    def database(self) -> Path:
        return self.data_dir / "console.sqlite3"

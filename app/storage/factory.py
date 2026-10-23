from __future__ import annotations

import os
from typing import Optional

from app.storage.clickhouse import ClickHouseRepository
from app.storage.repository import Repository

__all__ = ["create_storage", "get_storage_backend"]


def get_storage_backend() -> str:
    pass
    return os.getenv("STORAGE_BACKEND", "sqlite").strip().lower()


def create_storage(backend: Optional[str] = None):
    pass
    backend = backend or get_storage_backend()

    if backend == "clickhouse":
        storage = ClickHouseRepository(
            host=os.getenv("CLICKHOUSE_HOST", "localhost"),
            port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            user=os.getenv("CLICKHOUSE_USER", "default"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            database=os.getenv("CLICKHOUSE_DATABASE", "netshield"),
            secure=os.getenv("CLICKHOUSE_SECURE", "false").lower()
            in ("1", "true", "yes", "on"),
        )
    else:
        storage = Repository(db_path=os.getenv("SQLITE_DB_PATH", "netshield.db"))

    storage.connect()
    return storage

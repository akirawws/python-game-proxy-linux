from __future__ import annotations

import logging
import os
import threading
from typing import Optional

from app.storage.clickhouse import ClickHouseRepository
from app.storage.repository import Repository

__all__ = [
    "create_storage",
    "get_storage_backend",
    "get_config_storage",
    "get_metrics_storage",
    "reset_storage",
]

log = logging.getLogger("netshield.storage")

_lock = threading.RLock()
_config_storage: Optional[Repository] = None
_metrics_storage = None
_metrics_backend: str = "sqlite"


def get_storage_backend() -> str:
    return os.getenv("STORAGE_BACKEND", "sqlite").strip().lower()


def get_config_storage() -> Repository:
                                                                 
    global _config_storage
    with _lock:
        if _config_storage is None:
            _config_storage = Repository(
                db_path=os.getenv("SQLITE_DB_PATH", "netshield.db")
            )
            _config_storage.connect()
        return _config_storage


def _create_clickhouse() -> ClickHouseRepository:
    repository = ClickHouseRepository(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
        user=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "netshield"),
        secure=os.getenv("CLICKHOUSE_SECURE", "false").lower()
        in ("1", "true", "yes", "on"),
    )
    repository.connect()
    return repository


def get_metrics_storage():
                                                                     
    global _metrics_storage, _metrics_backend
    with _lock:
        if _metrics_storage is not None:
            return _metrics_storage

        config = get_config_storage()
        backend = get_storage_backend()
        if backend != "clickhouse":
            _metrics_storage = config
            _metrics_backend = "sqlite"
            return _metrics_storage

        try:
            _metrics_storage = _create_clickhouse()
            _metrics_backend = "clickhouse"
            config.set_system_status("clickhouse", "ok", "подключено")
        except Exception as exc:                                 
            log.error("ClickHouse недоступен, метрики читаются из SQLite")
            _metrics_storage = config
            _metrics_backend = "sqlite"
            config.set_system_status(
                "clickhouse",
                "error",
                f"ClickHouse недоступен: {type(exc).__name__}",
            )
        return _metrics_storage


def metrics_backend_name() -> str:
    ensure = get_metrics_storage()
    del ensure
    return _metrics_backend


def create_storage(backend: Optional[str] = None):
    backend = (backend or get_storage_backend()).strip().lower()
    if backend == "clickhouse":
        storage = _create_clickhouse()
    else:
        storage = Repository(db_path=os.getenv("SQLITE_DB_PATH", "netshield.db"))
        storage.connect()
    return storage


def reset_storage() -> None:
    global _config_storage, _metrics_storage, _metrics_backend
    with _lock:
        for storage in (_config_storage, _metrics_storage):
            if storage is None:
                continue
            try:
                storage.close()
            except Exception:
                pass
        _config_storage = None
        _metrics_storage = None
        _metrics_backend = "sqlite"

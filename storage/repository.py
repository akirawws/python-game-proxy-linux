"""Storage: репозиторий конфигурационных данных (SQLite/ClickHouse)."""

from __future__ import annotations

import sqlite3
from dataclasses import fields, is_dataclass
from datetime import datetime
from typing import Optional

from app.storage.models import TABLES, AnomalyEvent, SystemStatus, TrafficMetric

__all__ = ["Repository"]


class Repository:
    """Простой репозиторий на SQLite. Позже можно заменить на ClickHouse."""

    def __init__(self, db_path: str = "netshield.db") -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Repository not connected. Call .connect() first.")
        return self._conn

    def _init_schema(self) -> None:
        c = self.conn.cursor()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS protected_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                interface TEXT NOT NULL,
                max_pps INTEGER NOT NULL DEFAULT 0,
                max_bps INTEGER NOT NULL DEFAULT 0,
                max_new_tcp_per_s INTEGER NOT NULL DEFAULT 0,
                max_udp_pps INTEGER NOT NULL DEFAULT 0,
                max_new_sources INTEGER NOT NULL DEFAULT 0,
                max_connections INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS protected_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                FOREIGN KEY (server_id) REFERENCES protected_servers(id)
            );
            CREATE TABLE IF NOT EXISTS traffic_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                in_bytes INTEGER NOT NULL DEFAULT 0,
                out_bytes INTEGER NOT NULL DEFAULT 0,
                in_pps REAL NOT NULL DEFAULT 0,
                out_pps REAL NOT NULL DEFAULT 0,
                in_bps REAL NOT NULL DEFAULT 0,
                out_bps REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS connection_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                tcp_new INTEGER NOT NULL DEFAULT 0,
                udp_pps REAL NOT NULL DEFAULT 0,
                conntrack_count INTEGER NOT NULL DEFAULT 0,
                new_sources INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS anomaly_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                score REAL NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'info',
                details TEXT DEFAULT '',
                action_status TEXT NOT NULL DEFAULT 'proposed'
            );
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                action TEXT NOT NULL DEFAULT 'drop',
                expires_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TEXT,
                action TEXT NOT NULL,
                details TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS system_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ok',
                message TEXT DEFAULT '',
                updated_at TEXT
            );
            """
        )
        self.conn.commit()

    # ----- generic helpers -----

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat()

    def insert(self, table: str, model) -> int:
        if not is_dataclass(model):
            raise TypeError("model must be a dataclass")
        field_names = [f.name for f in fields(model) if f.name != "id"]
        values = [getattr(model, name) for name in field_names]
        values = [v.isoformat() if isinstance(v, datetime) else v for v in values]
        placeholders = ", ".join("?" for _ in field_names)
        columns = ", ".join(field_names)
        cur = self.conn.execute(
            f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", values
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def fetch_all(self, table: str, where: str = "", params: tuple = ()) -> list:
        sql = f"SELECT * FROM {table}"
        if where:
            sql += f" WHERE {where}"
        cur = self.conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def fetch_one(self, table: str, where: str, params: tuple = ()) -> Optional[dict]:
        sql = f"SELECT * FROM {table} WHERE {where} LIMIT 1"
        cur = self.conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row is not None else None

    def update(self, table: str, record_id: int, **kwargs) -> None:
        if not kwargs:
            return
        sets = ", ".join(f"{k}=?" for k in kwargs)
        values = list(kwargs.values()) + [record_id]
        self.conn.execute(
            f"UPDATE {table} SET {sets} WHERE id=?", values
        )
        self.conn.commit()

    # ----- domain methods -----

    def save_traffic_metric(self, metric: TrafficMetric) -> int:
        return self.insert("traffic_metrics", metric)

    def save_connection_metric(self, metric) -> int:
        return self.insert("connection_metrics", metric)

    def save_anomaly_event(self, event: AnomalyEvent) -> int:
        return self.insert("anomaly_events", event)

    def get_recent_traffic(
        self, server_id: int, limit: int = 100
    ) -> list[dict]:
        return self.fetch_all(
            "traffic_metrics",
            "server_id=? ORDER BY timestamp DESC LIMIT ?",
            (server_id, limit),
        )

    def get_recent_anomalies(
        self, server_id: int, limit: int = 50
    ) -> list[dict]:
        return self.fetch_all(
            "anomaly_events",
            "server_id=? ORDER BY timestamp DESC LIMIT ?",
            (server_id, limit),
        )

    def set_system_status(
        self, component: str, status: str, message: str = ""
    ) -> None:
        now = self._now()
        row = self.fetch_one(
            "system_status", "component=?", (component,)
        )
        if row is None:
            self.insert(
                "system_status",
                SystemStatus(
                    component=component,
                    status=status,
                    message=message,
                    updated_at=now,
                ),
            )
        else:
            self.update(
                "system_status",
                row["id"],
                status=status,
                message=message,
                updated_at=now,
            )

    def get_system_status(self, component: str) -> Optional[dict]:
        return self.fetch_one("system_status", "component=?", (component,))

from __future__ import annotations

import sqlite3
import threading
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from app.storage.models import TABLES, AnomalyEvent, AuditLog, SystemStatus, TrafficMetric

__all__ = ["Repository", "utcnow"]


def utcnow() -> datetime:
                                                          
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat()
    return value


SERVER_FIELDS = {
    "name",
    "ip",
    "interface",
    "max_pps",
    "max_bps",
    "max_new_tcp_per_s",
    "max_udp_pps",
    "max_new_sources",
    "max_connections",
    "is_active",
    "description",
    "service_type",
    "internal_ip",
    "internal_port",
    "profile",
}

PORT_FIELDS = {"port", "protocol", "service_type"}

RULE_FIELDS = {
    "server_id",
    "ip",
    "port",
    "protocol",
    "action",
    "expires_at",
    "is_active",
    "rule_type",
    "reason",
    "created_at",
}

                                                                               
EVENT_GROUP_FIELDS = {
    "severity": "e.severity",
    "event_type": "e.event_type",
    "protocol": "e.protocol",
    "action_status": "e.action_status",
}

DEFAULT_SETTINGS: dict[str, str] = {
    "detection_mode": "observation",
    "auto_actions_enabled": "false",
    "collection_interval_sec": "1",
    "confirmation_intervals": "3",
    "cooldown_seconds": "60",
    "metrics_retention_days": "7",
    "event_retention_days": "90",
    "max_concurrent_blocks": "20",
}


class Repository:

    def __init__(self, db_path: str = "netshield.db") -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

    def connect(self) -> None:
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
                                                                                  
                                                                                
                                                                             
        try:
            self._conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:                                                 
            pass
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
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

    def health_check(self) -> bool:
        try:
            self.conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

                                                                            

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
                interface TEXT NOT NULL DEFAULT '',
                max_pps INTEGER NOT NULL DEFAULT 0,
                max_bps INTEGER NOT NULL DEFAULT 0,
                max_new_tcp_per_s INTEGER NOT NULL DEFAULT 0,
                max_udp_pps INTEGER NOT NULL DEFAULT 0,
                max_new_sources INTEGER NOT NULL DEFAULT 0,
                max_connections INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                description TEXT NOT NULL DEFAULT '',
                service_type TEXT NOT NULL DEFAULT 'custom',
                internal_ip TEXT NOT NULL DEFAULT '',
                internal_port INTEGER NOT NULL DEFAULT 0,
                profile TEXT NOT NULL DEFAULT 'custom'
            );
            CREATE TABLE IF NOT EXISTS protected_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service_type TEXT NOT NULL DEFAULT 'custom',
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
                action_status TEXT NOT NULL DEFAULT 'proposed',
                protocol TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                action TEXT NOT NULL DEFAULT 'drop',
                expires_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                rule_type TEXT NOT NULL DEFAULT 'temporary',
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TEXT,
                action TEXT NOT NULL,
                details TEXT DEFAULT '',
                result TEXT NOT NULL DEFAULT 'ok'
            );
            CREATE TABLE IF NOT EXISTS system_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ok',
                message TEXT DEFAULT '',
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_server_ts
                ON traffic_metrics (server_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_conn_server_ts
                ON connection_metrics (server_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_server_ts
                ON anomaly_events (server_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_rules_server
                ON firewall_rules (server_id, is_active);
            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit_logs (timestamp);
            """
        )
        self._migrate()
        self.conn.commit()
        self._seed_settings()

    def _migrate(self) -> None:
        self._ensure_columns(
            "protected_servers",
            {
                "description": "TEXT NOT NULL DEFAULT ''",
                "service_type": "TEXT NOT NULL DEFAULT 'custom'",
                "internal_ip": "TEXT NOT NULL DEFAULT ''",
                "internal_port": "INTEGER NOT NULL DEFAULT 0",
                "profile": "TEXT NOT NULL DEFAULT 'custom'",
            },
        )
        self._ensure_columns(
            "protected_ports", {"service_type": "TEXT NOT NULL DEFAULT 'custom'"}
        )
        self._ensure_columns(
            "anomaly_events", {"protocol": "TEXT NOT NULL DEFAULT ''"}
        )
        self._ensure_columns(
            "firewall_rules",
            {
                "rule_type": "TEXT NOT NULL DEFAULT 'temporary'",
                "reason": "TEXT NOT NULL DEFAULT ''",
                "created_at": "TEXT",
            },
        )
        self._ensure_columns(
            "audit_logs", {"result": "TEXT NOT NULL DEFAULT 'ok'"}
        )

    def _ensure_columns(self, table: str, columns: dict[str, str]) -> None:
        existing = {
            row["name"]
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, definition in columns.items():
            if name not in existing:
                self.conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                )

    def _seed_settings(self) -> None:
        now = self._now()
        for key, value in DEFAULT_SETTINGS.items():
            self.conn.execute(
                "INSERT OR IGNORE INTO app_settings (key, value, updated_at) "
                "VALUES (?, ?, ?)",
                (key, value, now),
            )
        self.conn.commit()

                                                                            

    @staticmethod
    def _now() -> str:
        return utcnow().isoformat()

    def insert(self, table: str, model) -> int:
        if not is_dataclass(model):
            raise TypeError("model must be a dataclass")
        field_names = [f.name for f in fields(model) if f.name != "id"]
        values = [_iso(getattr(model, name)) for name in field_names]
        placeholders = ", ".join("?" for _ in field_names)
        columns = ", ".join(field_names)
        with self._lock:
            cur = self.conn.execute(
                f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", values
            )
            self.conn.commit()
        return int(cur.lastrowid)

    def insert_row(self, table: str, data: dict) -> int:
        data = {k: _iso(v) for k, v in data.items()}
        columns = ", ".join(data)
        placeholders = ", ".join("?" for _ in data)
        with self._lock:
            cur = self.conn.execute(
                f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
                list(data.values()),
            )
            self.conn.commit()
        return int(cur.lastrowid)

    def batch_insert(self, table: str, rows: list[dict]) -> None:
        if not rows:
            return
        keys = list(rows[0].keys())
        columns = ", ".join(keys)
        placeholders = ", ".join("?" for _ in keys)
        values = [[_iso(row.get(k)) for k in keys] for row in rows]
        with self._lock:
            self.conn.executemany(
                f"INSERT INTO {table} ({columns}) VALUES ({placeholders})",
                values,
            )
            self.conn.commit()

    def fetch_all(
        self,
        table: str,
        where: str = "",
        params: tuple = (),
        order_by: str = "",
    ) -> list[dict]:
        if where and where.strip().upper().startswith("ORDER BY"):
                                                                  
            order_by = where.strip()[len("ORDER BY") :].strip()
            where = ""
        sql = f"SELECT * FROM {table}"
        if where:
            sql += f" WHERE {where}"
        if order_by:
            sql += f" ORDER BY {order_by}"
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
        values = [_iso(v) for v in kwargs.values()] + [record_id]
        with self._lock:
            self.conn.execute(f"UPDATE {table} SET {sets} WHERE id=?", values)
            self.conn.commit()

    def delete(self, table: str, record_id: int) -> None:
        with self._lock:
            self.conn.execute(f"DELETE FROM {table} WHERE id=?", (record_id,))
            self.conn.commit()

                                                                            

    def save_traffic_metric(self, metric: TrafficMetric) -> int:
        return self.insert("traffic_metrics", metric)

    def save_connection_metric(self, metric) -> int:
        return self.insert("connection_metrics", metric)

    def save_anomaly_event(self, event: AnomalyEvent) -> int:
        return self.insert("anomaly_events", event)

    def get_recent_traffic(self, server_id: int, limit: int = 100) -> list[dict]:
        return self.fetch_all(
            "traffic_metrics",
            "server_id=? ORDER BY timestamp DESC LIMIT ?",
            (server_id, limit),
        )

    def get_recent_anomalies(self, server_id: int, limit: int = 50) -> list[dict]:
        return self.fetch_all(
            "anomaly_events",
            "server_id=? ORDER BY timestamp DESC LIMIT ?",
            (server_id, limit),
        )

                                                                            

    def list_servers(
        self, include_ports: bool = True, active_only: bool = False
    ) -> list[dict]:
        where = "is_active=1" if active_only else ""
        servers = self.fetch_all(
            "protected_servers", f"{where} ORDER BY id ASC" if where else "ORDER BY id ASC"
        )
        if include_ports:
            for server in servers:
                server["ports"] = self.list_ports(server["id"])
        return servers

    def get_server(self, server_id: int, include_ports: bool = True) -> Optional[dict]:
        server = self.fetch_one("protected_servers", "id=?", (server_id,))
        if server is not None and include_ports:
            server["ports"] = self.list_ports(server_id)
        return server

    def create_server(self, data: dict) -> int:
        payload = {k: v for k, v in data.items() if k in SERVER_FIELDS}
        if not payload.get("name") or not payload.get("ip"):
            raise ValueError("name and ip are required")
        return self.insert_row("protected_servers", payload)

    def update_server(self, server_id: int, data: dict) -> None:
        payload = {k: v for k, v in data.items() if k in SERVER_FIELDS}
        self.update("protected_servers", server_id, **payload)

    def delete_server(self, server_id: int) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM protected_ports WHERE server_id=?", (server_id,))
            self.conn.execute("DELETE FROM firewall_rules WHERE server_id=?", (server_id,))
            self.conn.execute("DELETE FROM protected_servers WHERE id=?", (server_id,))
            self.conn.commit()

    def list_ports(self, server_id: int) -> list[dict]:
        return self.fetch_all(
            "protected_ports", "server_id=? ORDER BY port ASC", (server_id,)
        )

    def replace_ports(self, server_id: int, ports: list[dict]) -> None:
        with self._lock:
            self.conn.execute(
                "DELETE FROM protected_ports WHERE server_id=?", (server_id,)
            )
            for item in ports:
                payload = {k: v for k, v in item.items() if k in PORT_FIELDS}
                payload["server_id"] = server_id
                self.conn.execute(
                    "INSERT INTO protected_ports (server_id, port, protocol, service_type) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        server_id,
                        int(payload.get("port", 0)),
                        payload.get("protocol", "tcp"),
                        payload.get("service_type", "custom"),
                    ),
                )
            self.conn.commit()

                                                                            

    @staticmethod
    def _bucket_expr(bucket_seconds: int) -> str:
        return (
            "(CAST(strftime('%s', timestamp) AS INTEGER) / "
            f"{int(bucket_seconds)}) * {int(bucket_seconds)}"
        )

    def query_traffic_series(
        self,
        server_id: Optional[int],
        date_from: datetime,
        date_to: datetime,
        bucket_seconds: int,
    ) -> list[dict]:
        bucket = self._bucket_expr(bucket_seconds)
        where = ["timestamp >= ?", "timestamp < ?"]
        params: list[Any] = [_iso(date_from), _iso(date_to)]
        if server_id is not None:
            where.append("server_id = ?")
            params.append(server_id)
        sql = (
            f"SELECT {bucket} AS bucket, "
            "sum(in_bytes) AS in_bytes, sum(out_bytes) AS out_bytes, "
            "avg(in_pps) AS in_pps, avg(out_pps) AS out_pps, "
            "avg(in_bps) AS in_bps, avg(out_bps) AS out_bps, "
            "count(*) AS samples "
            "FROM traffic_metrics WHERE "
            + " AND ".join(where)
            + " GROUP BY bucket ORDER BY bucket ASC"
        )
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def query_connection_series(
        self,
        server_id: Optional[int],
        date_from: datetime,
        date_to: datetime,
        bucket_seconds: int,
    ) -> list[dict]:
        bucket = self._bucket_expr(bucket_seconds)
        where = ["timestamp >= ?", "timestamp < ?"]
        params: list[Any] = [_iso(date_from), _iso(date_to)]
        if server_id is not None:
            where.append("server_id = ?")
            params.append(server_id)
        sql = (
            f"SELECT {bucket} AS bucket, "
            "avg(tcp_new) AS tcp_new, avg(udp_pps) AS udp_pps, "
            "avg(conntrack_count) AS conntrack_count, "
            "sum(new_sources) AS new_sources, count(*) AS samples "
            "FROM connection_metrics WHERE "
            + " AND ".join(where)
            + " GROUP BY bucket ORDER BY bucket ASC"
        )
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def latest_metric(self, server_id: Optional[int]) -> Optional[dict]:
        where = "" if server_id is None else "WHERE server_id = ?"
        params: tuple = () if server_id is None else (server_id,)
        with self._lock:
            row = self.conn.execute(
                "SELECT timestamp FROM traffic_metrics "
                f"{where} ORDER BY timestamp DESC LIMIT 1",
                params,
            ).fetchone()
        return dict(row) if row is not None else None

    def latest_event(self, server_id: Optional[int]) -> Optional[dict]:
        where = "" if server_id is None else "WHERE server_id = ?"
        params: tuple = () if server_id is None else (server_id,)
        with self._lock:
            row = self.conn.execute(
                "SELECT timestamp FROM anomaly_events "
                f"{where} ORDER BY timestamp DESC LIMIT 1",
                params,
            ).fetchone()
        return dict(row) if row is not None else None

                                                                            

    def _event_filters(
        self,
        server_id: Optional[int] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        protocol: Optional[str] = None,
        action_status: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> tuple[str, list[Any]]:
        where: list[str] = []
        params: list[Any] = []
        if server_id is not None:
            where.append("e.server_id = ?")
            params.append(server_id)
        if severity:
            where.append("e.severity = ?")
            params.append(severity)
        if event_type:
            where.append("e.event_type = ?")
            params.append(event_type)
        if protocol:
            where.append("e.protocol = ?")
            params.append(protocol)
        if action_status:
            where.append("e.action_status = ?")
            params.append(action_status)
        if date_from is not None:
            where.append("e.timestamp >= ?")
            params.append(_iso(date_from))
        if date_to is not None:
            where.append("e.timestamp < ?")
            params.append(_iso(date_to))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        return clause, params

    def list_events(
        self,
        server_id: Optional[int] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        protocol: Optional[str] = None,
        action_status: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        clause, params = self._event_filters(
            server_id, severity, event_type, protocol, action_status, date_from, date_to
        )
        page = max(1, int(page))
        page_size = min(200, max(1, int(page_size)))
        with self._lock:
            total = self.conn.execute(
                f"SELECT count(*) AS c FROM anomaly_events e{clause}", params
            ).fetchone()["c"]
            rows = self.conn.execute(
                "SELECT e.*, s.name AS server_name FROM anomaly_events e "
                "LEFT JOIN protected_servers s ON s.id = e.server_id"
                f"{clause} ORDER BY e.timestamp DESC LIMIT ? OFFSET ?",
                params + [page_size, (page - 1) * page_size],
            ).fetchall()
        return [dict(row) for row in rows], int(total)

    def event_stats(
        self,
        server_id: Optional[int] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        group_by: str = "severity",
    ) -> list[dict]:
        key = group_by if group_by in EVENT_GROUP_FIELDS else "severity"
        field = EVENT_GROUP_FIELDS[key]
        clause, params = self._event_filters(
            server_id=server_id, date_from=date_from, date_to=date_to
        )
        with self._lock:
            rows = self.conn.execute(
                f"SELECT {field} AS {key}, count(*) AS count, "
                "avg(e.score) AS avg_score, max(e.timestamp) AS last_event "
                f"FROM anomaly_events e{clause} GROUP BY {field} ORDER BY count DESC",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def count_events_since(self, since: datetime) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT count(*) AS c FROM anomaly_events WHERE timestamp >= ?",
                (_iso(since),),
            ).fetchone()
        return int(row["c"]) if row else 0

                                                                            

    def list_rules(
        self,
        server_id: Optional[int] = None,
        status: str = "all",
        now: Optional[datetime] = None,
    ) -> list[dict]:
        now = now or utcnow()
        where = ["r.is_active = 1"]
        params: list[Any] = []
        if server_id is not None:
            where.append("r.server_id = ?")
            params.append(server_id)
        if status == "temporary":
            where.append("r.expires_at IS NOT NULL AND r.expires_at > ?")
            params.append(_iso(now))
        elif status == "expired":
            where.append("r.expires_at IS NOT NULL AND r.expires_at <= ?")
            params.append(_iso(now))
        elif status == "permanent":
            where.append("r.expires_at IS NULL")
        with self._lock:
            rows = self.conn.execute(
                "SELECT r.*, s.name AS server_name FROM firewall_rules r "
                "LEFT JOIN protected_servers s ON s.id = r.server_id "
                "WHERE " + " AND ".join(where) + " ORDER BY r.id DESC",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def create_rule(self, data: dict) -> int:
        payload = {k: v for k, v in data.items() if k in RULE_FIELDS}
        payload.setdefault("created_at", utcnow())
        if isinstance(payload.get("created_at"), datetime):
            payload["created_at"] = _iso(payload["created_at"])
        return self.insert_row("firewall_rules", payload)

    def deactivate_rule(self, rule_id: int) -> bool:
        row = self.fetch_one("firewall_rules", "id=?", (rule_id,))
        if row is None:
            return False
        self.update("firewall_rules", rule_id, is_active=0)
        return True

    def get_rule(self, rule_id: int) -> Optional[dict]:
        return self.fetch_one("firewall_rules", "id=?", (rule_id,))

    def get_active_rules(self, server_id: Optional[int] = None) -> list[dict]:
                                                                        
        return self.list_rules(server_id=server_id, status="all")

                                                                            

    def append_audit(
        self,
        action: str,
        details: str = "",
        user_id: Optional[int] = None,
        result: str = "ok",
    ) -> int:
        return self.insert(
            "audit_logs",
            AuditLog(
                user_id=user_id,
                timestamp=utcnow(),
                action=action,
                details=details,
                result=result,
            ),
        )

    def list_audit(
        self,
        action: Optional[str] = None,
        result: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        where: list[str] = []
        params: list[Any] = []
        if action:
            where.append("a.action LIKE ?")
            params.append(f"%{action}%")
        if result:
            where.append("a.result = ?")
            params.append(result)
        if date_from is not None:
            where.append("a.timestamp >= ?")
            params.append(_iso(date_from))
        if date_to is not None:
            where.append("a.timestamp < ?")
            params.append(_iso(date_to))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        page = max(1, int(page))
        page_size = min(200, max(1, int(page_size)))
        with self._lock:
            total = self.conn.execute(
                f"SELECT count(*) AS c FROM audit_logs a{clause}", params
            ).fetchone()["c"]
            rows = self.conn.execute(
                "SELECT a.*, u.login AS user_login FROM audit_logs a "
                "LEFT JOIN users u ON u.id = a.user_id"
                f"{clause} ORDER BY a.timestamp DESC LIMIT ? OFFSET ?",
                params + [page_size, (page - 1) * page_size],
            ).fetchall()
        return [dict(row) for row in rows], int(total)

                                                                            

    def get_settings(self) -> dict[str, str]:
        rows = self.fetch_all("app_settings")
        return {row["key"]: row["value"] for row in rows}

    def update_settings(self, values: dict[str, str]) -> dict[str, str]:
        now = self._now()
        with self._lock:
            for key, value in values.items():
                self.conn.execute(
                    "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "updated_at=excluded.updated_at",
                    (key, str(value), now),
                )
            self.conn.commit()
        return self.get_settings()

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.fetch_one("app_settings", "key=?", (key,))
        return row["value"] if row is not None else default

    def list_system_status(self) -> list[dict]:
        return self.fetch_all("system_status", "ORDER BY component ASC")

    def set_system_status(self, component: str, status: str, message: str = "") -> None:
        now = self._now()
        row = self.fetch_one("system_status", "component=?", (component,))
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

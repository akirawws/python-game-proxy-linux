from __future__ import annotations

import os
from dataclasses import fields, is_dataclass
from datetime import datetime
from typing import Optional

from app.storage.models import AnomalyEvent, ConnectionMetric, TrafficMetric

__all__ = ["ClickHouseRepository", "create_clickhouse_repository"]

                                                                            
                                                  
DEFAULT_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
DEFAULT_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
DEFAULT_USER = os.getenv("CLICKHOUSE_USER", "default")
DEFAULT_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
DEFAULT_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "netshield")
DEFAULT_SECURE = os.getenv("CLICKHOUSE_SECURE", "false").lower() in ("1", "true", "yes", "on")
DEFAULT_VERIFY = os.getenv("CLICKHOUSE_VERIFY", "false").lower() in ("1", "true", "yes", "on")

                                                                              
EVENT_GROUP_COLUMNS = {
    "severity": "severity",
    "event_type": "event_type",
    "protocol": "protocol",
    "action_status": "action_status",
}


class ClickHouseRepository:
    pass

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        user: str = DEFAULT_USER,
        password: str = DEFAULT_PASSWORD,
        database: str = DEFAULT_DATABASE,
        secure: bool = DEFAULT_SECURE,
        verify: bool = DEFAULT_VERIFY,
        connect_timeout: int = 10,
        send_receive_timeout: int = 30,
    ) -> None:
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._database = database
        self._secure = secure
        self._verify = verify
        self._connect_timeout = connect_timeout
        self._send_receive_timeout = send_receive_timeout
        self._client = None

    @property
    def client(self):
        if self._client is None:
            raise RuntimeError("ClickHouse not connected. Call .connect() first.")
        return self._client

    def connect(self) -> None:
        from clickhouse_connect import get_client

        self._client = get_client(
            host=self._host,
            port=self._port,
            user=self._user,
            password=self._password,
            database=self._database,
            secure=self._secure,
            verify=self._verify,
            connect_timeout=self._connect_timeout,
            send_receive_timeout=self._send_receive_timeout,
        )
        self._client.ping()
        self.create_schema()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "ClickHouseRepository":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    def health_check(self) -> bool:
        pass
        try:
            self.client.ping()
            return True
        except Exception:
            return False

                                                                             

    def create_schema(self) -> None:
        pass
        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS traffic_metrics (
                server_id UInt32,
                timestamp DateTime64(3) 'UTC',
                in_bytes Int64 NOT NULL DEFAULT 0,
                out_bytes Int64 NOT NULL DEFAULT 0,
                in_pps Float64 NOT NULL DEFAULT 0,
                out_pps Float64 NOT NULL DEFAULT 0,
                in_bps Float64 NOT NULL DEFAULT 0,
                out_bps Float64 NOT NULL DEFAULT 0
            ) ENGINE = MergeTree
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (server_id, timestamp)
            TTL timestamp + INTERVAL 30 DAY
            SETTINGS index_granularity = 8192;
            """
        )
        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS connection_metrics (
                server_id UInt32,
                timestamp DateTime64(3) 'UTC',
                tcp_new Int64 NOT NULL DEFAULT 0,
                udp_pps Float64 NOT NULL DEFAULT 0,
                conntrack_count Int64 NOT NULL DEFAULT 0,
                new_sources Int64 NOT NULL DEFAULT 0
            ) ENGINE = MergeTree
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (server_id, timestamp)
            TTL timestamp + INTERVAL 30 DAY
            SETTINGS index_granularity = 8192;
            """
        )
        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS anomaly_events (
                server_id UInt32,
                timestamp DateTime64(3) 'UTC',
                event_type LowCardinality(String) NOT NULL DEFAULT '',
                score Float64 NOT NULL DEFAULT 0,
                severity LowCardinality(String) NOT NULL DEFAULT 'info',
                details String NOT NULL DEFAULT '',
                action_status LowCardinality(String) NOT NULL DEFAULT 'proposed',
                protocol LowCardinality(String) NOT NULL DEFAULT ''
            ) ENGINE = MergeTree
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (server_id, timestamp)
            TTL timestamp + INTERVAL 90 DAY
            SETTINGS index_granularity = 8192;
            """
        )
        self._migrate_columns()

    def _migrate_columns(self) -> None:
                                
        try:
            self.client.command(
                "ALTER TABLE anomaly_events "
                "ADD COLUMN IF NOT EXISTS protocol "
                "LowCardinality(String) NOT NULL DEFAULT ''"
            )
        except Exception:
                                                                          
            pass

                                                                              

    @staticmethod
    def _model_row(model) -> tuple:
        if not is_dataclass(model):
            raise TypeError("model must be a dataclass")
        return tuple(
            getattr(model, f.name) for f in fields(model) if f.name != "id"
        )

                                                                              

    def insert_traffic_metric(self, metric: TrafficMetric) -> None:
        self.insert_traffic_metrics([metric])

    def insert_traffic_metrics(self, metrics: list[TrafficMetric]) -> None:
        if not metrics:
            return
        columns = [f.name for f in fields(TrafficMetric) if f.name != "id"]
        rows = [self._model_row(m) for m in metrics]
        self.client.insert("traffic_metrics", rows, column_names=columns)

    def insert_connection_metric(self, metric: ConnectionMetric) -> None:
        self.insert_connection_metrics([metric])

    def insert_connection_metrics(self, metrics: list[ConnectionMetric]) -> None:
        if not metrics:
            return
        columns = [f.name for f in fields(ConnectionMetric) if f.name != "id"]
        rows = [self._model_row(m) for m in metrics]
        self.client.insert("connection_metrics", rows, column_names=columns)

    def insert_anomaly_event(self, event: AnomalyEvent) -> None:
        self.insert_anomaly_events([event])

    def insert_anomaly_events(self, events: list[AnomalyEvent]) -> None:
        if not events:
            return
        columns = [f.name for f in fields(AnomalyEvent) if f.name != "id"]
        rows = [self._model_row(e) for e in events]
        self.client.insert("anomaly_events", rows, column_names=columns)

                                                                              

    def get_recent_traffic(
        self, server_id: int, limit: int = 100
    ) -> list[dict]:
        result = self.client.query(
            """
            SELECT server_id, timestamp, in_bytes, out_bytes, in_pps, out_pps, in_bps, out_bps
            FROM traffic_metrics
            WHERE server_id = {server_id:UInt32}
            ORDER BY timestamp DESC
            LIMIT {limit:UInt32}
            """,
            parameters={"server_id": server_id, "limit": limit},
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def get_recent_anomalies(
        self, server_id: int, limit: int = 50
    ) -> list[dict]:
        result = self.client.query(
            """
            SELECT server_id, timestamp, event_type, score, severity, details, action_status
            FROM anomaly_events
            WHERE server_id = {server_id:UInt32}
            ORDER BY timestamp DESC
            LIMIT {limit:UInt32}
            """,
            parameters={"server_id": server_id, "limit": limit},
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def get_traffic_summary(
        self, server_id: int, date_from: datetime, date_to: datetime
    ) -> dict:
        result = self.client.query(
            """
            SELECT
                sum(in_bytes) AS total_in_bytes,
                sum(out_bytes) AS total_out_bytes,
                avg(in_pps) AS avg_in_pps,
                max(in_pps) AS max_in_pps,
                count() AS rows_count
            FROM traffic_metrics
            WHERE server_id = {server_id:UInt32}
              AND timestamp >= {from:DateTime64}
              AND timestamp < {to:DateTime64}
            """,
            parameters={"server_id": server_id, "from": date_from, "to": date_to},
        )
        row = result.result_rows[0] if result.result_rows else []
        return dict(zip(result.column_names, row)) if row else {}

    def get_anomaly_stats(
        self, server_id: int, date_from: datetime, date_to: datetime
    ) -> list[dict]:
        result = self.client.query(
            """
            SELECT severity, count() AS cnt, avg(score) AS avg_score
            FROM anomaly_events
            WHERE server_id = {server_id:UInt32}
              AND timestamp >= {from:DateTime64}
              AND timestamp < {to:DateTime64}
            GROUP BY severity
            ORDER BY cnt DESC
            """,
            parameters={"server_id": server_id, "from": date_from, "to": date_to},
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]


    def query_traffic_series(
        self,
        server_id: Optional[int],
        date_from: datetime,
        date_to: datetime,
        bucket_seconds: int,
    ) -> list[dict]:
        server_filter = "" if server_id is None else "AND server_id = {server_id:UInt32}"
        result = self.client.query(
            f"""
            SELECT intDiv(toUnixTimestamp(timestamp), {{bucket:UInt32}}) * {{bucket:UInt32}} AS bucket,
                   sum(in_bytes) AS in_bytes,
                   sum(out_bytes) AS out_bytes,
                   avg(in_pps) AS in_pps,
                   avg(out_pps) AS out_pps,
                   avg(in_bps) AS in_bps,
                   avg(out_bps) AS out_bps,
                   count() AS samples
            FROM traffic_metrics
            WHERE timestamp >= {{from:DateTime64}}
              AND timestamp < {{to:DateTime64}}
              {server_filter}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            parameters={
                "bucket": int(bucket_seconds),
                "from": date_from,
                "to": date_to,
                "server_id": server_id or 0,
            },
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def query_connection_series(
        self,
        server_id: Optional[int],
        date_from: datetime,
        date_to: datetime,
        bucket_seconds: int,
    ) -> list[dict]:
        server_filter = "" if server_id is None else "AND server_id = {server_id:UInt32}"
        result = self.client.query(
            f"""
            SELECT intDiv(toUnixTimestamp(timestamp), {{bucket:UInt32}}) * {{bucket:UInt32}} AS bucket,
                   avg(tcp_new) AS tcp_new,
                   avg(udp_pps) AS udp_pps,
                   avg(conntrack_count) AS conntrack_count,
                   sum(new_sources) AS new_sources,
                   count() AS samples
            FROM connection_metrics
            WHERE timestamp >= {{from:DateTime64}}
              AND timestamp < {{to:DateTime64}}
              {server_filter}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            parameters={
                "bucket": int(bucket_seconds),
                "from": date_from,
                "to": date_to,
                "server_id": server_id or 0,
            },
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

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
        where, parameters = self._event_where(
            server_id, severity, event_type, protocol, action_status, date_from, date_to
        )
        page = max(1, int(page))
        page_size = min(200, max(1, int(page_size)))
        parameters.update({"limit": page_size, "offset": (page - 1) * page_size})
        result = self.client.query(
            f"""
            SELECT server_id, timestamp, event_type, score, severity, details,
                   action_status, protocol
            FROM anomaly_events
            {where}
            ORDER BY timestamp DESC
            LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """,
            parameters=parameters,
        )
        rows = [dict(zip(result.column_names, row)) for row in result.result_rows]
        total = self._count_events(where, parameters)
        return rows, total

    def _event_where(
        self,
        server_id: Optional[int],
        severity: Optional[str],
        event_type: Optional[str],
        protocol: Optional[str],
        action_status: Optional[str],
        date_from: Optional[datetime],
        date_to: Optional[datetime],
    ) -> tuple[str, dict]:
        conditions: list[str] = []
        parameters: dict = {}
        if server_id is not None:
            conditions.append("server_id = {server_id:UInt32}")
            parameters["server_id"] = int(server_id)
        if severity:
            conditions.append("severity = {severity:String}")
            parameters["severity"] = severity
        if event_type:
            conditions.append("event_type = {event_type:String}")
            parameters["event_type"] = event_type
        if protocol:
            conditions.append("protocol = {protocol:String}")
            parameters["protocol"] = protocol
        if action_status:
            conditions.append("action_status = {action_status:String}")
            parameters["action_status"] = action_status
        if date_from is not None:
            conditions.append("timestamp >= {from:DateTime64}")
            parameters["from"] = date_from
        if date_to is not None:
            conditions.append("timestamp < {to:DateTime64}")
            parameters["to"] = date_to
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return where, parameters

    def _count_events(self, where: str, parameters: dict) -> int:
        clean = {
            key: value
            for key, value in parameters.items()
            if key not in ("limit", "offset")
        }
        result = self.client.query(
            f"SELECT count() AS c FROM anomaly_events{where}", parameters=clean
        )
        return int(result.result_rows[0][0]) if result.result_rows else 0

    def event_stats(
        self,
        server_id: Optional[int] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        group_by: str = "severity",
    ) -> list[dict]:
        column = EVENT_GROUP_COLUMNS.get(group_by, "severity")
        key = group_by if group_by in EVENT_GROUP_COLUMNS else "severity"
        where, parameters = self._event_where(
            server_id, None, None, None, None, date_from, date_to
        )
        result = self.client.query(
            f"""
            SELECT {column} AS {key}, count() AS count, avg(score) AS avg_score,
                   max(timestamp) AS last_event
            FROM anomaly_events
            {where}
            GROUP BY {column}
            ORDER BY count DESC
            """,
            parameters=parameters,
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def latest_metric(self, server_id: Optional[int]) -> Optional[dict]:
        where = "" if server_id is None else "WHERE server_id = {server_id:UInt32}"
        result = self.client.query(
            f"SELECT max(timestamp) AS timestamp FROM traffic_metrics {where}",
            parameters={"server_id": int(server_id or 0)},
        )
        if not result.result_rows or result.result_rows[0][0] is None:
            return None
        return {"timestamp": result.result_rows[0][0]}

    def latest_event(self, server_id: Optional[int]) -> Optional[dict]:
        where = "" if server_id is None else "WHERE server_id = {server_id:UInt32}"
        result = self.client.query(
            f"SELECT max(timestamp) AS timestamp FROM anomaly_events {where}",
            parameters={"server_id": int(server_id or 0)},
        )
        if not result.result_rows or result.result_rows[0][0] is None:
            return None
        return {"timestamp": result.result_rows[0][0]}


def create_clickhouse_repository() -> ClickHouseRepository:
    pass
    return ClickHouseRepository(
        host=os.getenv("CLICKHOUSE_HOST", DEFAULT_HOST),
        port=int(os.getenv("CLICKHOUSE_PORT", str(DEFAULT_PORT))),
        user=os.getenv("CLICKHOUSE_USER", DEFAULT_USER),
        password=os.getenv("CLICKHOUSE_PASSWORD", DEFAULT_PASSWORD),
        database=os.getenv("CLICKHOUSE_DATABASE", DEFAULT_DATABASE),
        secure=os.getenv("CLICKHOUSE_SECURE", str(DEFAULT_SECURE)).lower()
        in ("1", "true", "yes", "on"),
        verify=os.getenv("CLICKHOUSE_VERIFY", str(DEFAULT_VERIFY)).lower()
        in ("1", "true", "yes", "on"),
    )

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class User:
    id: Optional[int] = None
    login: str = ""
    password_hash: str = ""
    is_admin: bool = False
    created_at: Optional[datetime] = None


@dataclass
class ProtectedServer:
    id: Optional[int] = None
    name: str = ""
    ip: str = ""
    interface: str = ""
    max_pps: int = 0
    max_bps: int = 0
    max_new_tcp_per_s: int = 0
    max_udp_pps: int = 0
    max_new_sources: int = 0
    max_connections: int = 0
    is_active: bool = True


@dataclass
class ProtectedPort:
    id: Optional[int] = None
    server_id: int = 0
    port: int = 0
    protocol: str = "tcp"


@dataclass
class TrafficMetric:
    id: Optional[int] = None
    server_id: int = 0
    timestamp: Optional[datetime] = None
    in_bytes: int = 0
    out_bytes: int = 0
    in_pps: float = 0.0
    out_pps: float = 0.0
    in_bps: float = 0.0
    out_bps: float = 0.0


@dataclass
class ConnectionMetric:
    id: Optional[int] = None
    server_id: int = 0
    timestamp: Optional[datetime] = None
    tcp_new: int = 0
    udp_pps: float = 0.0
    conntrack_count: int = 0
    new_sources: int = 0


@dataclass
class AnomalyEvent:
    id: Optional[int] = None
    server_id: int = 0
    timestamp: Optional[datetime] = None
    event_type: str = ""
    score: float = 0.0
    severity: str = "info"
    details: str = ""
    action_status: str = "proposed"


@dataclass
class FirewallRule:
    id: Optional[int] = None
    server_id: int = 0
    ip: str = ""
    port: int = 0
    protocol: str = "tcp"
    action: str = "drop"
    expires_at: Optional[datetime] = None
    is_active: bool = True


@dataclass
class AuditLog:
    id: Optional[int] = None
    user_id: Optional[int] = None
    timestamp: Optional[datetime] = None
    action: str = ""
    details: str = ""


@dataclass
class SystemStatus:
    id: Optional[int] = None
    component: str = ""
    status: str = "ok"
    message: str = ""
    updated_at: Optional[datetime] = None


TABLES: dict[str, type] = {
    "users": User,
    "protected_servers": ProtectedServer,
    "protected_ports": ProtectedPort,
    "traffic_metrics": TrafficMetric,
    "connection_metrics": ConnectionMetric,
    "anomaly_events": AnomalyEvent,
    "firewall_rules": FirewallRule,
    "audit_logs": AuditLog,
    "system_status": SystemStatus,
}

__all__ = [
    "User",
    "ProtectedServer",
    "ProtectedPort",
    "TrafficMetric",
    "ConnectionMetric",
    "AnomalyEvent",
    "FirewallRule",
    "AuditLog",
    "SystemStatus",
    "TABLES",
]

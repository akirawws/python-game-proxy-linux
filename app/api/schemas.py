from __future__ import annotations

from typing import Optional, List

from pydantic import BaseModel, Field, field_validator, ConfigDict

class ServerBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    ip: str
    interface: str = ""
    service_type: str = "custom"
    internal_ip: str = ""
    internal_port: int = 0
    profile: str = "custom"
    description: str = ""
    is_active: bool = True
    max_pps: int = 0
    max_bps: int = 0
    max_new_tcp_per_s: int = 0
    max_udp_pps: int = 0
    max_new_sources: int = 0
    max_connections: int = 0

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("некорректный IP-адрес")
        return value

    @field_validator("interface")
    @classmethod
    def _validate_interface(cls, value: str) -> str:
        import re
        if value and not re.match(r'^[a-zA-Z0-9_.:-]+$', value):
            raise ValueError("недопустимый интерфейс")
        return value

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("имя не должно содержать переносы строк")
        return value

    @field_validator("profile")
    @classmethod
    def _validate_profile(cls, value: str) -> str:
        if value not in ("web", "game", "custom"):
            raise ValueError("недопустимый профиль")
        return value

class ServerCreate(ServerBase):
    ports: List[dict] = []

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: List[dict]) -> List[dict]:
        seen = set()
        for p in value:
            port = p.get("port")
            proto = p.get("protocol", "tcp")
            if port < 1 or port > 65535:
                raise ValueError("порт вне диапазона")
            if proto not in ("tcp", "udp", "both"):
                raise ValueError("недопустимый протокол")
            key = (port, proto)
            if key in seen:
                raise ValueError("дубликаты портов")
            seen.add(key)
        return value

class ServerUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = None
    ip: Optional[str] = None
    interface: Optional[str] = None
    service_type: Optional[str] = None
    internal_ip: Optional[str] = None
    internal_port: Optional[int] = None
    profile: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    max_pps: Optional[int] = None
    max_bps: Optional[int] = None
    max_new_tcp_per_s: Optional[int] = None
    max_udp_pps: Optional[int] = None
    max_new_sources: Optional[int] = None
    max_connections: Optional[int] = None

    @field_validator("ip")
    @classmethod
    def _validate_ip_empty(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value == "":
            raise ValueError("ip не может быть пустым")
        return value

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and ("\n" in value or "\r" in value):
            raise ValueError("имя не должно содержать переносы строк")
        return value

class PortItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service_type: str = "custom"

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        if value not in ("tcp", "udp", "both"):
            raise ValueError("недопустимый протокол")
        return value

class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server_id: int
    action: str
    ip: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    ttl_seconds: Optional[int] = None
    reason: str = ""

    @field_validator("action")
    @classmethod
    def _validate_action(cls, value: str) -> str:
        allowed = {"drop", "rate_limit", "alert", "block_source", "block_port"}
        if value not in allowed:
            raise ValueError("недопустимое действие")
        return value

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        if value not in ("tcp", "udp", "both"):
            raise ValueError("недопустимый протокол")
        return value

class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detection_mode: Optional[str] = None
    auto_actions_enabled: Optional[bool] = None
    collection_interval_sec: Optional[int] = None
    confirmation_intervals: Optional[int] = None
    cooldown_seconds: Optional[int] = None
    max_concurrent_blocks: Optional[int] = None
    metrics_retention_days: Optional[int] = None
    event_retention_days: Optional[int] = None

    @field_validator("detection_mode")
    @classmethod
    def _validate_mode(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ("observation", "auto"):
            raise ValueError("недопустимый режим обнаружения")
        return value
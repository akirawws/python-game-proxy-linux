from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

from app.firewall.policy import ActionType
from app.storage.models import FirewallRule
from app.storage.repository import Repository

__all__ = [
    "ValidationError",
    "FirewallCommand",
    "validate_ip",
    "validate_port",
    "validate_protocol",
    "validate_expires_at",
    "validate_command",
]


class ValidationError(ValueError):
    pass


ALLOWED_PROTOCOLS = {"tcp", "udp", "both"}


class FirewallCommand:
    def __init__(
        self,
        action: str,
        server_id: int,
        ip: str = "",
        port: Optional[int] = None,
        protocol: str = "tcp",
        expires_at: Optional[datetime] = None,
        reason: str = "",
        ttl_seconds: int = 0,
    ) -> None:
        self.action = action
        self.server_id = server_id
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.expires_at = expires_at
        self.reason = reason
        self.ttl_seconds = ttl_seconds


def validate_ip(value: str) -> str:
    if value in ("", "any"):
        return value
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError(f"некорректный IP-адрес: {value}")
    return value


def validate_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"порт должен быть числом: {value!r}")
    if port < 1 or port > 65535:
        raise ValidationError(f"порт вне диапазона 1-65535: {port}")
    return port


def validate_protocol(value: str) -> str:
    proto = (value or "tcp").strip().lower()
    if proto == "":
        return "tcp"
    if proto not in ALLOWED_PROTOCOLS:
        raise ValidationError(f"недопустимый протокол: {proto}")
    return proto


def validate_expires_at(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    if value <= datetime.now(timezone.utc):
        raise ValidationError("время истечения должно быть в будущем")
    return value


def validate_command(cmd: FirewallCommand, repo: Repository, policy) -> FirewallCommand:
    try:
        ActionType(cmd.action)
    except ValueError:
        raise ValidationError(f"неизвестное действие: {cmd.action}")
    if ActionType(cmd.action) not in policy.allowed_actions:
        raise ValidationError(f"действие {cmd.action} не разрешено для профиля {policy.profile}")
    server = repo.fetch_one("protected_servers", "id=?", (cmd.server_id,))
    if server is None:
        raise ValidationError(f"сервер {cmd.server_id} не найден")
    if cmd.ip:
        validate_ip(cmd.ip)
    if cmd.port is not None:
        cmd.port = validate_port(cmd.port)
        if cmd.port:
            ports = repo.list_ports(cmd.server_id)
            protected = any(
                int(p["port"]) == cmd.port and p["protocol"] in (cmd.protocol, "both")
                for p in ports
            )
            if not protected:
                raise ValidationError(f"порт {cmd.port} не принадлежит серверу {cmd.server_id}")
    cmd.protocol = validate_protocol(cmd.protocol)
    if cmd.expires_at is not None:
        cmd.expires_at = validate_expires_at(cmd.expires_at)
    return cmd


def rule_to_command(rule: FirewallRule) -> FirewallCommand:
    return FirewallCommand(
        action=rule.action,
        server_id=rule.server_id,
        ip=rule.ip,
        port=rule.port or None,
        protocol=rule.protocol,
        expires_at=rule.expires_at,
        reason=rule.reason,
    )


def command_to_rule_data(cmd: FirewallCommand, rule_id: int = 0) -> dict:
    from datetime import datetime

    now = datetime.utcnow()
    expires_at = None
    if cmd.ttl_seconds and cmd.ttl_seconds > 0:
        from datetime import timedelta

        expires_at = now + timedelta(seconds=cmd.ttl_seconds)
    return {
        "id": rule_id,
        "server_id": cmd.server_id,
        "ip": cmd.ip,
        "port": cmd.port or 0,
        "protocol": cmd.protocol,
        "action": cmd.action,
        "expires_at": expires_at,
        "is_active": True,
        "rule_type": "temporary" if expires_at else "permanent",
        "reason": cmd.reason,
        "created_at": now,
    }

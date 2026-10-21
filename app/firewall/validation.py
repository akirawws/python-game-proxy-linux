"""Firewall: валидация параметров перед созданием правила.

Проверяет IP-адрес, порт, протокол, срок действия и принадлежность цели
защищаемому серверу. Любые произвольные команды от Detector или пользователя
отвергаются — разрешено только структурированное решение из перечня ActionType
(ТЗ §6.8).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from app.firewall.policy import ActionType

__all__ = [
    "ValidationError",
    "FirewallCommand",
    "ValidatedCommand",
    "validate_ip",
    "validate_port",
    "validate_protocol",
    "validate_expires_at",
    "validate_command",
]


class ValidationError(ValueError):
    """Ошибка валидации защитной команды."""


@dataclass(frozen=True)
class FirewallCommand:
    """Структурированное решение Detector/администратора.

    Содержит только поля из разрешённого перечня действий. Shell-команды и
    произвольные строки здесь не передаются.
    """

    action: ActionType
    server_id: int
    ip: str = ""
    port: int = 0
    protocol: str = "tcp"
    expires_at: Optional[datetime] = None
    reason: str = ""
    source: str = "detector"  # detector / admin / system


@dataclass(frozen=True)
class ValidatedCommand:
    """Окнончательно проверенная команда, готовая к применению Rule Manager."""

    action: ActionType
    server_id: int
    ip: str
    port: int
    protocol: str
    expires_at: Optional[datetime]
    reason: str
    source: str


def validate_ip(ip: str) -> str:
    """Проверка IPv4/IPv6-адреса. Пустая строка и 'any' допускаются."""
    if not ip or ip == "any":
        return ip
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValidationError(f"некорректный IP-адрес: {ip}") from exc
    return ip


def validate_port(port) -> int:
    """Проверка порта (1–65535)."""
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"порт должен быть целым числом: {port!r}") from exc
    if not (1 <= p <= 65535):
        raise ValidationError(f"порт вне диапазона 1–65535: {p}")
    return p


def validate_protocol(proto: str) -> str:
    """Проверка протокола: tcp / udp / both."""
    p = (proto or "tcp").lower()
    if p not in {"tcp", "udp", "both"}:
        raise ValidationError(f"неподдерживаемый протокол: {proto!r}")
    return p


def validate_expires_at(expires_at) -> Optional[datetime]:
    """Срок действия временного правила: должен быть в будущем (UTC)."""
    if expires_at is None:
        return None
    if isinstance(expires_at, datetime):
        dt = expires_at
    else:
        dt = datetime.fromisoformat(str(expires_at))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt <= datetime.now(timezone.utc):
        raise ValidationError("срок действия должен быть в будущем")
    return dt


def validate_command(cmd: FirewallCommand, repo, policy) -> ValidatedCommand:
    """Полная валидация команды защиты (ТЗ §4.1, §6.6, §6.8).

    Проверки:
      * действие из разрешённого перечня ActionType;
      * действие разрешено политикой сервера;
      * сервер существует и активен;
      * порт/протокол принадлежат защищаемому серверу (для портовых действий);
      * срок действия — в будущем, если задан;
      * любой неверный параметр — отказ, без применения правила.
    """

    # Любое действие должно быть из жёстко заданного перечня —
    # произвольные команды от Detector/пользователя недопустимы (§6.8).
    if not isinstance(cmd.action, ActionType):
        raise ValidationError(f"неизвестное действие: {cmd.action!r}")

    server = repo.fetch_one("protected_servers", "id=?", (cmd.server_id,))
    if server is None:
        raise ValidationError(f"сервер {cmd.server_id} не найден")
    if not server.get("is_active"):
        raise ValidationError(f"сервер {cmd.server_id} не активен")

    if not policy.is_action_allowed(cmd.action):
        raise ValidationError(
            f"действие {cmd.action.value} не разрешено политикой сервера "
            f"({policy.profile.value})"
        )

    port = 0
    protocol = "tcp"
    port_actions = {
        ActionType.RATE_LIMIT,
        ActionType.PORT_RULE,
        ActionType.DROP,
    }
    if cmd.action in port_actions:
        port = validate_port(cmd.port)
        protocol = validate_protocol(cmd.protocol)

        if protocol == "both":
            protected = repo.fetch_one(
                "protected_ports",
                "server_id=? AND port=?",
                (cmd.server_id, port),
            )
        else:
            protected = repo.fetch_one(
                "protected_ports",
                "server_id=? AND port=? AND protocol=?",
                (cmd.server_id, port, protocol),
            )
        if protected is None:
            raise ValidationError(
                f"порт {port}/{protocol} не защищён сервером {cmd.server_id}"
            )

    expires_at = validate_expires_at(cmd.expires_at)

    ip = validate_ip(cmd.ip) if cmd.ip else str(server.get("ip", ""))

    return ValidatedCommand(
        action=cmd.action,
        server_id=int(server["id"]),
        ip=ip,
        port=port,
        protocol=protocol,
        expires_at=expires_at,
        reason=cmd.reason or "",
        source=cmd.source,
    )

"""Firewall: модель политики защиты сервера.

Описывает, какие защитные действия разрешены для сервера, какие лимиты аномалий
применяются, какой профиль фильтрации выбран (Web / игровой / пользовательский)
и сколько блокировок может быть активных одновременно.

Соответствует разделам ТЗ:
  * §4.1 — тип сервиса (Web / игровой / пользовательский) и профиль фильтрации;
  * §6.1 — фиксированные пороговые значения (PPS, трафик, новые TCP, UDP PPS,
           новые источники, соединения);
  * §6.5 — шкала риска → выбираемое Rule Manager действие;
  * §6.6 — защита от ложных срабатываний: минимум последовательных превышений,
           время подтверждения, cooldown, белый список, максимум одновременных
           блокировок, режим наблюдения;
  * §6.8 — строгий набор разрешённых защитных действий.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional


class ActionType(str, Enum):
    """Разрешённые защитные действия (ТЗ §6.8).

    Rule Manager выполняет только действия из этого перечисления. Произвольные
    команды от Detector или пользователя недопустимы.
    """

    LOG_ONLY = "log_only"  # зарегистрировать событие без изменения фильтрации
    RATE_LIMIT = "rate_limit"  # установить ограничение скорости
    LIMIT_SOURCE = "limit_source"  # временно ограничить конкретный источник
    PORT_RULE = "port_rule"  # применить правило к заданному порту и протоколу
    DROP = "drop"  # отклонить пакеты, однозначно нарушающие политику
    EXPIRE = "expire"  # снять истёкшее временное правило


class PolicyProfile(str, Enum):
    """Профиль фильтрации сервера (ТЗ §4.1).

    Для Web и игровых профилей задаются рекомендуемые стартовые лимиты
    (DEFAULT_LIMITS); администратор может переопределить любое значение.
    """

    WEB = "web"  # Web-сервер
    GAME = "game"  # игровой сервер
    CUSTOM = "custom"  # пользовательский профиль


# ---------------------------------------------------------------------------
# Рекомендуемые стартовые лимиты по профилям (ТЗ §4.1, §6.1).
# Ноль означает «лимит не задан / не ограничен».
# ---------------------------------------------------------------------------

DEFAULT_LIMITS: dict[PolicyProfile, dict[str, int]] = {
    PolicyProfile.WEB: {
        "max_pps": 50_000,
        "max_inbound_bps": 100_000_000,  # ~100 Мбит/с входящего трафика
        "max_new_tcp_per_s": 5_000,
        "max_udp_pps": 10_000,
        "max_new_sources": 1_000,
        "max_connections": 50_000,
        "max_concurrent_blocks": 50,
    },
    PolicyProfile.GAME: {
        "max_pps": 100_000,
        "max_inbound_bps": 50_000_000,  # ~50 Мбит/с входящего трафика
        "max_new_tcp_per_s": 1_000,
        "max_udp_pps": 80_000,
        "max_new_sources": 500,
        "max_connections": 2_000,
        "max_concurrent_blocks": 100,
    },
    PolicyProfile.CUSTOM: {
        "max_pps": 0,
        "max_inbound_bps": 0,
        "max_new_tcp_per_s": 0,
        "max_udp_pps": 0,
        "max_new_sources": 0,
        "max_connections": 0,
        "max_concurrent_blocks": 10,
    },
}

# Разрешённые действия по умолчанию для профиля (ТЗ §6.8).
# Для Web — исходим из того, что за NAT могут быть десятки легитимных
# пользователей на одном IP (§6.4), поэтому блокировку источника не включаем
# по умолчанию.
DEFAULT_ACTIONS: dict[PolicyProfile, set[ActionType]] = {
    PolicyProfile.WEB: {
        ActionType.LOG_ONLY,
        ActionType.RATE_LIMIT,
        ActionType.PORT_RULE,
    },
    PolicyProfile.GAME: {
        ActionType.LOG_ONLY,
        ActionType.RATE_LIMIT,
        ActionType.LIMIT_SOURCE,
        ActionType.PORT_RULE,
    },
    PolicyProfile.CUSTOM: set(ActionType),
}

DEFAULT_MAX_CONCURRENT_BLOCKS = 20  # ТЗ §6.6: ограничение числа активных блокировок

# Пороговая шкала риска (ТЗ §6.5).
RISK_NORMAL_MAX = 1  # 0–1 — только сбор статистики
RISK_LOW_MAX = 3  # 2–3 — запись предупреждения
RISK_MEDIUM_MAX = 5  # 4–5 — повторная проверка, ограничение скорости
# 6 и выше — применение заранее утверждённого защитного правила.


@dataclass
class ServerPolicy:
    """Политика защиты одного защищаемого сервера.

    Связана с записью ``ProtectedServer`` (хранится один профиль на сервер).
    Все лимиты задаются администратором; значения из ``DEFAULT_LIMITS`` —
    рекомендуемые стартовые точки для профилей Web и Game.
    """

    # Профиль фильтрации (ТЗ §4.1).
    profile: PolicyProfile = PolicyProfile.CUSTOM
    # Режим наблюдения: аномалии détectруются и фиксируются, но фильтрация
    # не изменяется (ТЗ §6.6).
    observe_mode: bool = False
    # Белый список доверенных адресов — никогда не блокируются (ТЗ §6.6).
    whitelist: set[str] = field(default_factory=set)
    # Разрешённые защитные действия (ТЗ §6.8).
    allowed_actions: set[ActionType] = field(default_factory=set)

    # Максимальные лимиты аномалий (ТЗ §4.1, §6.1).
    max_pps: int = 0
    max_inbound_bps: int = 0
    max_new_tcp_per_s: int = 0
    max_udp_pps: int = 0
    max_new_sources: int = 0
    max_connections: int = 0

    # Защита от ложных срабатываний (ТЗ §6.6).
    min_consecutive_violations: int = 3
    confirmation_window_s: int = 10
    cooldown_s: int = 60
    max_concurrent_blocks: int = DEFAULT_MAX_CONCURRENT_BLOCKS

    def __post_init__(self) -> None:
        if not self.allowed_actions:
            self.allowed_actions = set(
                DEFAULT_ACTIONS.get(self.profile, {ActionType.LOG_ONLY})
            )

    # ------------------------------------------------------------------
    # Фабрика по профилю
    # ------------------------------------------------------------------

    @classmethod
    def for_profile(cls, profile: PolicyProfile) -> "ServerPolicy":
        """Создать политику со стандартными лимитами заданного профиля."""
        limits = DEFAULT_LIMITS.get(profile, {})
        actions = set(
            DEFAULT_ACTIONS.get(profile, {ActionType.LOG_ONLY})
        )
        return cls(
            profile=profile,
            allowed_actions=actions,
            max_concurrent_blocks=limits.get(
                "max_concurrent_blocks", DEFAULT_MAX_CONCURRENT_BLOCKS
            ),
            max_pps=limits.get("max_pps", 0),
            max_inbound_bps=limits.get("max_inbound_bps", 0),
            max_new_tcp_per_s=limits.get("max_new_tcp_per_s", 0),
            max_udp_pps=limits.get("max_udp_pps", 0),
            max_new_sources=limits.get("max_new_sources", 0),
            max_connections=limits.get("max_connections", 0),
        )

    # ------------------------------------------------------------------
    # Проверки разрешённых действий (ТЗ §6.8)
    # ------------------------------------------------------------------

    def is_action_allowed(self, action: ActionType) -> bool:
        """True, если действие разрешено политикой сервера."""
        return action in self.allowed_actions

    def can_add_block(self, current_active_blocks: int) -> bool:
        """True, если можно добавить ещё одну блокировку (макс одновременных).

        ТЗ §6.6: ограничение числа одновременно активных блокировок.
        """
        if self.max_concurrent_blocks <= 0:
            return False
        return current_active_blocks < self.max_concurrent_blocks

    def remaining_blocks(self, current_active_blocks: int) -> int:
        """Сколько ещё блокировок можно добавить до достижения лимита."""
        if self.max_concurrent_blocks <= 0:
            return 0
        return max(0, self.max_concurrent_blocks - current_active_blocks)

    def is_whitelisted(self, ip: str) -> bool:
        """True, если адрес в белом списке доверенных источников (ТЗ §6.6)."""
        return ip in self.whitelist

    def is_in_cooldown(self, last_action_at: Optional[datetime]) -> bool:
        """True, если с последнего действия ещё не прошёл cooldown (ТЗ §6.6)."""
        if self.cooldown_s <= 0 or last_action_at is None:
            return False
        return datetime.now(timezone.utc) - last_action_at < timedelta(
            seconds=self.cooldown_s
        )

    # ------------------------------------------------------------------
    # Шкала риска → действие (ТЗ §6.5)
    # ------------------------------------------------------------------

    def action_for_severity(self, score: float) -> ActionType:
        """Подобрать действие по баллу риска с учётом разрешённых действий.

        Шкала (ТЗ §6.5):
          0–1   — нормальный, только статистика            → LOG_ONLY
          2–3   — низкий, предупреждение                   → LOG_ONLY
          4–5   — средний, ограничение скорости            → RATE_LIMIT
          6+    — высокий, защитное правило                → DROP

        Если вычисленное действие не в ``allowed_actions``, возвращается
        ближайшее более мягкое разрешённое действие (минимум — LOG_ONLY).
        """
        if score <= RISK_NORMAL_MAX:
            base = ActionType.LOG_ONLY
        elif score <= RISK_LOW_MAX:
            base = ActionType.LOG_ONLY
        elif score <= RISK_MEDIUM_MAX:
            base = ActionType.RATE_LIMIT
        else:
            base = ActionType.DROP

        if self.is_action_allowed(base):
            return base

        # Падаем к ближайшему более мягкому разрешённому действию.
        fallback_order = [
            ActionType.LOG_ONLY,
            ActionType.RATE_LIMIT,
            ActionType.LIMIT_SOURCE,
            ActionType.PORT_RULE,
            ActionType.DROP,
        ]
        for action in fallback_order:
            if self.is_action_allowed(action):
                return action
        return ActionType.LOG_ONLY

    # ------------------------------------------------------------------
    # Проверка метрик на превышение лимитов (ТЗ §4.1, §6.1)
    # ------------------------------------------------------------------

    def check_limits(
        self,
        *,
        pps: int = 0,
        inbound_bps: int = 0,
        new_tcp_per_s: int = 0,
        udp_pps: int = 0,
        new_sources: int = 0,
        connections: int = 0,
    ) -> tuple[bool, list[str]]:
        """Проверить метрики интервала на превышение лимитов политики.

        Возвращает ``(is_anomaly, reasons)``. Лимит, равный 0, не проверяется.
        """
        reasons: list[str] = []

        if self.max_pps and pps > self.max_pps:
            reasons.append(
                f"pps {pps} > limit {self.max_pps}"
            )
        if self.max_inbound_bps and inbound_bps > self.max_inbound_bps:
            reasons.append(
                f"inbound_bps {inbound_bps} > limit {self.max_inbound_bps}"
            )
        if self.max_new_tcp_per_s and new_tcp_per_s > self.max_new_tcp_per_s:
            reasons.append(
                f"new_tcp_per_s {new_tcp_per_s} > limit {self.max_new_tcp_per_s}"
            )
        if self.max_udp_pps and udp_pps > self.max_udp_pps:
            reasons.append(
                f"udp_pps {udp_pps} > limit {self.max_udp_pps}"
            )
        if self.max_new_sources and new_sources > self.max_new_sources:
            reasons.append(
                f"new_sources {new_sources} > limit {self.max_new_sources}"
            )
        if self.max_connections and connections > self.max_connections:
            reasons.append(
                f"connections {connections} > limit {self.max_connections}"
            )

        return (len(reasons) > 0, reasons)

    # ------------------------------------------------------------------
    # Сериализация для хранения в конфигурации / БД
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Сериализовать политику в словарь (JSON-совместимо)."""
        return {
            "profile": self.profile.value,
            "observe_mode": self.observe_mode,
            "whitelist": sorted(self.whitelist),
            "allowed_actions": sorted(a.value for a in self.allowed_actions),
            "max_pps": self.max_pps,
            "max_inbound_bps": self.max_inbound_bps,
            "max_new_tcp_per_s": self.max_new_tcp_per_s,
            "max_udp_pps": self.max_udp_pps,
            "max_new_sources": self.max_new_sources,
            "max_connections": self.max_connections,
            "min_consecutive_violations": self.min_consecutive_violations,
            "confirmation_window_s": self.confirmation_window_s,
            "cooldown_s": self.cooldown_s,
            "max_concurrent_blocks": self.max_concurrent_blocks,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ServerPolicy":
        """Создать политику из словаря (обратное к to_dict)."""
        try:
            profile = PolicyProfile(data.get("profile", PolicyProfile.CUSTOM.value))
        except ValueError:
            profile = PolicyProfile.CUSTOM

        allowed_actions: set[ActionType] = set()
        for name in data.get("allowed_actions", []) or []:
            try:
                allowed_actions.add(ActionType(name))
            except ValueError:
                continue
        if not allowed_actions:
            allowed_actions = set(
                DEFAULT_ACTIONS.get(profile, {ActionType.LOG_ONLY})
            )

        return cls(
            profile=profile,
            observe_mode=bool(data.get("observe_mode", False)),
            whitelist=set(data.get("whitelist", []) or []),
            allowed_actions=allowed_actions,
            max_pps=int(data.get("max_pps", 0) or 0),
            max_inbound_bps=int(data.get("max_inbound_bps", 0) or 0),
            max_new_tcp_per_s=int(data.get("max_new_tcp_per_s", 0) or 0),
            max_udp_pps=int(data.get("max_udp_pps", 0) or 0),
            max_new_sources=int(data.get("max_new_sources", 0) or 0),
            max_connections=int(data.get("max_connections", 0) or 0),
            min_consecutive_violations=int(
                data.get("min_consecutive_violations", 3) or 3
            ),
            confirmation_window_s=int(
                data.get("confirmation_window_s", 10) or 10
            ),
            cooldown_s=int(data.get("cooldown_s", 60) or 60),
            max_concurrent_blocks=int(
                data.get("max_concurrent_blocks", DEFAULT_MAX_CONCURRENT_BLOCKS)
                or DEFAULT_MAX_CONCURRENT_BLOCKS
            ),
        )


__all__ = [
    "ActionType",
    "PolicyProfile",
    "ServerPolicy",
    "DEFAULT_LIMITS",
    "DEFAULT_ACTIONS",
    "DEFAULT_MAX_CONCURRENT_BLOCKS",
    "RISK_NORMAL_MAX",
    "RISK_LOW_MAX",
    "RISK_MEDIUM_MAX",
]

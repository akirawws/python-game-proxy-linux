"""Firewall: Rule Manager — применение разрешённых защитных правил.

Rule Manager получает структурированное решение от Detector и выбирает действие
только из заранее заданного списка (ТЗ §6.8). Не выполняет произвольных команд,
не меняет фильтрацию в режиме наблюдения, защищает от ложных срабатываний
(whitelist, лимит одновременных блокировок, cooldown, постепенное усиление,
ограничение частоты обновления) и журналирует каждое действие с причиной.

Соответствует разделам ТЗ:
  * §6.6 — защита от ложных срабатываний, режим наблюдения, автоматическое
           снятие временных правил;
  * §6.8 — строгий набор разрешённых действий;
  * §8.1 — истечение временных правил контролируется приложением;
  * §11 — обновление правил ограничено по частоте.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Protocol, Set

from app.firewall.policy import ActionType, ServerPolicy
from app.firewall.validation import (
    FirewallCommand,
    ValidatedCommand,
    ValidationError,
    validate_command,
)
from app.storage.models import AuditLog, FirewallRule
from app.storage.repository import Repository

__all__ = [
    "RuleDecision",
    "ApplyResult",
    "RuleManager",
    "NftablesBackend",
]


class NftablesBackend(Protocol):
    """Абстракция над nftables.

    Реальная реализация вызывает утилиту `nft` (отдельный процесс с
    минимальными привилегиями, ТЗ §11). В тестах подставляется подделка, так
    как Rule Manager не должен зависеть от наличия root/nftables.
    """

    def apply_rule(
        self,
        *,
        server_id: int,
        ip: str,
        port: int,
        protocol: str,
        action: str,
        expires_at: Optional[datetime],
        rule_id: int,
    ) -> None:
        """Применить правило в nftables."""

    def remove_rule(self, rule_id: int) -> None:
        """Удалить правило из nftables по идентификатору."""

    def list_active_rules(self) -> list[dict]:
        """Список активных правил в nftables."""

    def ensure_base_rules(
        self, server_id: int, ip: str, ports: list[int]
    ) -> None:
        """Базовые правила фильтрации, которые остаются при недоступности Python."""


# Блокирующие действия — учитываются в лимите одновременных блокировок (§6.6).
_BLOCKING_ACTIONS: Set[ActionType] = {
    ActionType.LIMIT_SOURCE,
    ActionType.DROP,
    ActionType.PORT_RULE,
}

# Порядок жёсткости действий для постепенного усиления (§6.6).
_STRENGTH_ORDER = [
    ActionType.LOG_ONLY,
    ActionType.RATE_LIMIT,
    ActionType.PORT_RULE,
    ActionType.LIMIT_SOURCE,
    ActionType.DROP,
]

_DEFAULT_MIN_UPDATE_INTERVAL_S = 5.0  # ТЗ §11: ограничение частоты обновлений


@dataclass(frozen=True)
class RuleDecision:
    """Структурированное решение от Detector (ТЗ §6.8)."""

    action: ActionType
    server_id: int
    ip: str = ""
    port: int = 0
    protocol: str = "tcp"
    expires_at: Optional[datetime] = None
    reason: str = ""
    score: float = 0.0
    source: str = "detector"

    def to_command(self) -> FirewallCommand:
        return FirewallCommand(
            action=self.action,
            server_id=self.server_id,
            ip=self.ip,
            port=self.port,
            protocol=self.protocol,
            expires_at=self.expires_at,
            reason=self.reason,
            source=self.source,
        )


@dataclass
class ApplyResult:
    """Результат применения правила."""

    status: str  # applied / proposed / ignored / rejected / expired
    rule_id: Optional[int] = None
    reason: str = ""
    error: Optional[str] = None


class RuleManager:
    """Менеджер защитных правил одного или нескольких серверов."""

    def __init__(
        self,
        repo: Repository,
        policy: ServerPolicy,
        backend: Optional[NftablesBackend] = None,
        *,
        observe_mode: bool = False,
        auto_enabled: bool = True,
        min_update_interval_s: float = _DEFAULT_MIN_UPDATE_INTERVAL_S,
    ) -> None:
        self.repo = repo
        self.policy = policy
        self.backend = backend
        self.observe_mode = observe_mode
        self.auto_enabled = auto_enabled
        self.min_update_interval = timedelta(seconds=min_update_interval_s)

        # Защита от ложных срабатываний (ТЗ §6.6).
        self._whitelist: Set[str] = set(policy.whitelist)
        self._cooldown_s = policy.cooldown_s
        self._max_blocks = policy.max_concurrent_blocks

        # Состояние в памяти (сбрасывается при перезапуске; persistent
        # состояние хранится в firewall_rules / audit_logs).
        self._last_update: dict[int, datetime] = {}
        self._last_action: dict[int, datetime] = {}
        self._last_applied: dict[tuple[int, str], ActionType] = {}

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _audit(
        self,
        action: str,
        server_id: int,
        reason: str,
        details: str = "",
        user_id: Optional[int] = None,
    ) -> None:
        """Запись события в audit_logs (причина каждого действия, §6.6)."""
        try:
            self.repo.insert(
                "audit_logs",
                AuditLog(
                    user_id=user_id,
                    timestamp=self._now(),
                    action=action,
                    details=(
                        f"server_id={server_id}; reason={reason}; {details}"
                    ).strip("; "),
                ),
            )
        except Exception:
            # Аудит не должен ломать применение правила.
            pass

    def _persist_rule(
        self,
        cmd: ValidatedCommand,
        action: ActionType,
        now: datetime,
    ) -> Optional[int]:
        """Сохранить правило в firewall_rules и применить через nftables.

        При ошибке бэкенда правило помечается неактивным и фиксируется ошибка.
        """
        rule = FirewallRule(
            server_id=cmd.server_id,
            ip=cmd.ip,
            port=cmd.port,
            protocol=cmd.protocol,
            action=action.value,
            expires_at=cmd.expires_at,
            is_active=True,
        )
        rule_id = self.repo.insert("firewall_rules", rule)

        try:
            if self.backend is not None:
                self.backend.apply_rule(
                    server_id=cmd.server_id,
                    ip=cmd.ip,
                    port=cmd.port,
                    protocol=cmd.protocol,
                    action=action.value,
                    expires_at=cmd.expires_at,
                    rule_id=rule_id,
                )
        except Exception as exc:  # pragma: no cover - бэкенд недоступен
            self.repo.update("firewall_rules", rule_id, is_active=False)
            self._audit(
                "error", cmd.server_id, cmd.reason,
                f"ошибка применения в nftables: {exc}",
            )
            return None

        self._audit(
            "apply", cmd.server_id, cmd.reason,
            f"rule_id={rule_id}; action={action.value}; ip={cmd.ip}; "
            f"port={cmd.port}; protocol={cmd.protocol}",
        )
        return rule_id

    def _count_active_blocks(self, server_id: int) -> int:
        """Число активных блокирующих правил сервера (ТЗ §6.6)."""
        now = self._now().isoformat()
        rows = self.repo.fetch_all(
            "firewall_rules",
            (
                "server_id=? AND is_active=1 AND action IN (?, ?, ?) "
                "AND (expires_at IS NULL OR expires_at > ?)"
            ),
            (server_id, "drop", "limit_source", "port_rule", now),
        )
        return len(rows)

    def _is_in_cooldown(self, server_id: int) -> bool:
        last = self._last_action.get(server_id)
        return self.policy.is_in_cooldown(last)

    def _escalate(
        self, server_id: int, action: ActionType, ip: str
    ) -> ActionType:
        """Постепенное усиление фильтрации (ТЗ §6.6).

        Если для той же цели последнее применённое действие совпадает с
        текущим, переходим к следующему более строгому разрешённому действию.
        """
        key = (server_id, ip)
        last = self._last_applied.get(key)
        if last is not None and last == action:
            try:
                idx = _STRENGTH_ORDER.index(action)
            except ValueError:
                return action
            if idx + 1 < len(_STRENGTH_ORDER):
                stronger = _STRENGTH_ORDER[idx + 1]
                if self.policy.is_action_allowed(stronger):
                    return stronger
        return action

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def is_action_allowed(self, action: ActionType) -> bool:
        return self.policy.is_action_allowed(action)

    def get_active_blocks(self, server_id: int) -> int:
        """Число текущих активных блокировок сервера."""
        return self._count_active_blocks(server_id)

    def apply_decision(self, decision: RuleDecision) -> ApplyResult:
        """Применить структурированное решение Detector.

        Возвращает ApplyResult со статусом:
          * proposed   — режим наблюдения или автоматика отключена;
          * ignored    — whitelist / cooldown / слишком частое обновление;
          * rejected   — не прошла валидация или лимит блокировок;
          * applied    — правило применено в nftables и сохранено;
          * expired    — правило истекло (см. expire_rules).
        """
        now = self._now()

        # Режим наблюдения / ручное отключение автоматических действий (§6.6, §11).
        if self.observe_mode or not self.auto_enabled:
            self._audit(
                "propose", decision.server_id, decision.reason,
                f"observe_mode={self.observe_mode}, auto_enabled={self.auto_enabled}",
            )
            return ApplyResult(
                status="proposed",
                reason="режим наблюдения или автоматика отключена",
            )

        # Валидация структурированной команды (§6.8).
        try:
            cmd = validate_command(decision.to_command(), self.repo, self.policy)
        except ValidationError as exc:
            self._audit("reject", decision.server_id, decision.reason, str(exc))
            return ApplyResult(status="rejected", reason=str(exc))

        # Белый список доверенных адресов (§6.6).
        if cmd.ip and self.policy.is_whitelisted(cmd.ip):
            self._audit("ignore", cmd.server_id, cmd.reason, "ip в белом списке")
            return ApplyResult(status="ignored", reason="адрес в белом списке")

        # Cooldown — период, в течение которого одинаковые действия не повторяются (§6.6).
        if self._is_in_cooldown(cmd.server_id):
            self._audit("ignore", cmd.server_id, cmd.reason, "cooldown")
            return ApplyResult(status="ignored", reason="cooldown не истёк")

        # Ограничение частоты обновления правил, чтобы колебания нагрузки
        # не вызывали постоянных изменений (§11).
        last_upd = self._last_update.get(cmd.server_id)
        if last_upd is not None and now - last_upd < self.min_update_interval:
            self._audit(
                "ignore", cmd.server_id, cmd.reason, "слишком частое обновление"
            )
            return ApplyResult(
                status="ignored",
                reason="превышена допустимая частота обновления правил",
            )

        # Постепенное усиление фильтрации (§6.6).
        final_action = self._escalate(cmd.server_id, cmd.action, cmd.ip)

        # Лимит одновременных блокировок (§6.6).
        if final_action in _BLOCKING_ACTIONS:
            active = self._count_active_blocks(cmd.server_id)
            if not self.policy.can_add_block(active):
                self._audit(
                    "reject", cmd.server_id, cmd.reason,
                    f"активных блокировок: {active} / {self._max_blocks}",
                )
                return ApplyResult(
                    status="rejected",
                    reason="достигнут лимит одновременных блокировок",
                )

        rule_id = self._persist_rule(cmd, final_action, now)
        if rule_id is None:
            return ApplyResult(
                status="rejected",
                reason=cmd.reason,
                error="не удалось применить правило в nftables",
            )

        self._last_update[cmd.server_id] = now
        self._last_action[cmd.server_id] = now
        self._last_applied[(cmd.server_id, cmd.ip)] = final_action

        return ApplyResult(
            status="applied",
            rule_id=rule_id,
            reason=cmd.reason,
        )

    def expire_rules(self, now: Optional[datetime] = None) -> list[int]:
        """Снять истёкшие временные правила (контролируется приложением, §8.1).

        Возвращает список идентификаторов снятых правил.
        """
        if now is None:
            now = self._now()
        now_iso = now.isoformat()

        rows = self.repo.fetch_all(
            "firewall_rules",
            (
                "is_active=1 AND expires_at IS NOT NULL AND expires_at <= ?"
            ),
            (now_iso,),
        )
        removed: list[int] = []
        for row in rows:
            rule_id = int(row["id"])
            try:
                if self.backend is not None:
                    self.backend.remove_rule(rule_id)
            except Exception as exc:  # pragma: no cover
                self._audit(
                    "error", int(row["server_id"]),
                    f"expire rule {rule_id}",
                    f"ошибка удаления из nftables: {exc}",
                )
            self.repo.update("firewall_rules", rule_id, is_active=False)
            self._audit(
                "expire", int(row["server_id"]),
                f"срок действия истёк", f"rule_id={rule_id}",
            )
            removed.append(rule_id)
        return removed

    def sync_with_nftables(self) -> dict[str, int]:
        """Синхронизация состояния правил при перезапуске Python.

        Сравнивает firewall_rules (активные, не истёкшие) с фактическими
        правилами nftables и восстанавливает недостающие. Базовые правила
        остаются при недоступности Python (§11).
        """
        now_iso = self._now().isoformat()
        db_rules = self.repo.fetch_all(
            "firewall_rules",
            (
                "is_active=1 AND (expires_at IS NULL OR expires_at > ?)"
            ),
            (now_iso,),
        )
        db_keys = {
            (
                int(r["server_id"]), str(r["ip"]), int(r["port"]),
                str(r["protocol"]), str(r["action"]),
            ): int(r["id"])
            for r in db_rules
        }

        reapplied = 0
        missing = 0
        if self.backend is not None:
            nft_rules = self.backend.list_active_rules()
            nft_keys = {
                (
                    int(r.get("server_id", 0)), str(r.get("ip", "")),
                    int(r.get("port", 0)), str(r.get("protocol", "tcp")),
                    str(r.get("action", "drop")),
                )
                for r in nft_rules
            }
            for key, rule_id in db_keys.items():
                if key not in nft_keys:
                    row = next(r for r in db_rules if int(r["id"]) == rule_id)
                    try:
                        expires_at_raw = row.get("expires_at")
                        self.backend.apply_rule(
                            server_id=int(row["server_id"]),
                            ip=str(row["ip"]),
                            port=int(row["port"]),
                            protocol=str(row["protocol"]),
                            action=str(row["action"]),
                            expires_at=(
                                datetime.fromisoformat(expires_at_raw)
                                if expires_at_raw
                                else None
                            ),
                            rule_id=rule_id,
                        )
                        reapplied += 1
                    except Exception:  # pragma: no cover
                        missing += 1
        return {"db_rules": len(db_rules), "reapplied": reapplied, "missing": missing}

    def ensure_base_rules(self, server_id: int, ip: str, ports: list[int]) -> None:
        """Убедиться, что базовые правила фильтрации сервера присутствуют.

        Вызывается при старте / недоступности Python — базовая фильтрация
        остаётся даже если Python сервис остановлен (§11).
        """
        if self.backend is not None:
            self.backend.ensure_base_rules(server_id, ip, ports)
            self._audit(
                "base_rules", server_id,
                "базовые правила фильтрации",
                f"ip={ip}; ports={ports}",
            )

    def set_observe_mode(self, enabled: bool) -> None:
        """Включить/выключить режим наблюдения (ручное управление)."""
        self.observe_mode = bool(enabled)
        self._audit(
            "config", str(self.policy.profile),
            "режим наблюдения",
            f"observe_mode={self.observe_mode}",
        )

    def set_auto_enabled(self, enabled: bool) -> None:
        """Ручное включение/отключение автоматических действий (§11)."""
        self.auto_enabled = bool(enabled)
        self._audit(
            "config", str(self.policy.profile),
            "автоматические действия",
            f"auto_enabled={self.auto_enabled}",
        )

    def add_whitelist(self, ip: str) -> None:
        self._whitelist.add(ip)
        self.policy.whitelist.add(ip)

    def remove_whitelist(self, ip: str) -> None:
        self._whitelist.discard(ip)
        self.policy.whitelist.discard(ip)

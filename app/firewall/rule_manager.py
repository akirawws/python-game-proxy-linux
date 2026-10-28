from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.firewall.policy import ActionType, PolicyProfile
from app.firewall.validation import FirewallCommand, validate_command
from app.storage.models import FirewallRule
from app.storage.repository import Repository, utcnow

__all__ = [
    "ApplyResult",
    "RuleDecision",
    "NftablesBackend",
    "RuleManager",
]


class NftablesBackend:
    def apply_rule(
        self,
        *,
        server_id: int,
        ip: str,
        port: int,
        protocol: str,
        action: str,
        expires_at,
        rule_id: int,
    ) -> None:
        raise NotImplementedError

    def remove_rule(self, rule_id: int) -> None:
        raise NotImplementedError

    def list_active_rules(self) -> list[dict]:
        return []

    def ensure_base_rules(self, server_id: int, ip: str, ports: list[int]) -> None:
        pass


@dataclass
class RuleDecision:
    action: str
    server_id: int
    ip: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    reason: str = ""
    score: float = 0.0
    ttl_seconds: int = 0
    expires_at: Optional[datetime] = None


@dataclass
class ApplyResult:
    status: str
    rule_id: Optional[int] = None
    reason: str = field(default_factory=str)


class RuleManager:
    def __init__(
        self,
        repo: Repository,
        policy=None,
        backend=None,
        observe_mode: bool = False,
        auto_enabled: bool = True,
        min_update_interval_s: int = 0,
    ) -> None:
        self.repo = repo
        self.policy = policy
        self.backend = backend or NftablesBackend()
        self.observe_mode = observe_mode
        self.auto_enabled = auto_enabled
        self.min_update_interval_s = min_update_interval_s
        self._last_update: dict[str, float] = {}

    def set_auto_enabled(self, enabled: bool) -> None:
        self.auto_enabled = enabled
        self.repo.append_audit(
            "config", details=f"автоприменение правил: {'вкл' if enabled else 'выкл'}"
        )

    def set_observe_mode(self, enabled: bool) -> None:
        self.observe_mode = enabled
        self.repo.append_audit(
            "config", details=f"режим наблюдения: {'вкл' if enabled else 'выкл'}"
        )

    def _now(self) -> datetime:
        return utcnow()

    def _in_cooldown(self, server_id: int, ip: str) -> bool:
        if not self.policy or self.policy.cooldown_s <= 0:
            return False
        key = f"{server_id}:{ip}"
        last = self._last_update.get(key)
        if last is None:
            return False
        return (self._now().timestamp() - last) < self.policy.cooldown_s

    def _touch(self, server_id: int, ip: str) -> None:
        self._last_update[f"{server_id}:{ip}"] = self._now().timestamp()

    def _interval_not_passed(self, server_id: int, ip: str) -> bool:
        if self.min_update_interval_s <= 0:
            return False
        key = f"{server_id}:{ip}"
        last = self._last_update.get(key)
        if last is None:
            return False
        return (self._now().timestamp() - last) < self.min_update_interval_s

    def _count_active_blocks(self, server_id: int) -> int:
        rules = self.repo.get_active_rules(server_id)
        return sum(1 for r in rules if r["action"] in ("drop", "block_source"))

    def _has_rate_limit(self, server_id: int, ip: str, port: int) -> bool:
        rules = self.repo.get_active_rules(server_id)
        for r in rules:
            if r["action"] == "rate_limit" and r["ip"] == ip and int(r["port"] or 0) == port:
                return True
        return False

    def _persist_rule(
        self, server_id: int, ip: str, port: int, protocol: str, action: str,
        expires_at, reason: str, score: float,
    ) -> int:
        rule_type = "temporary" if expires_at else "permanent"
        rule_data = {
            "server_id": server_id,
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "action": action,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "is_active": 1,
            "rule_type": rule_type,
            "reason": reason,
            "created_at": utcnow().isoformat(),
        }
        return self.repo.insert_row("firewall_rules", rule_data)

    def apply_decision(self, decision: RuleDecision) -> ApplyResult:
        if self.policy is None:
            return ApplyResult(status="rejected", reason="политика не задана")

        if decision.ip in self.policy.whitelist:
            return ApplyResult(status="ignored", reason="адрес в белом списке")

        cmd = FirewallCommand(
            action=decision.action,
            server_id=decision.server_id,
            ip=decision.ip,
            port=decision.port,
            protocol=decision.protocol,
            expires_at=decision.expires_at,
            reason=decision.reason,
            ttl_seconds=decision.ttl_seconds,
        )
        try:
            validate_command(cmd, self.repo, self.policy)
        except Exception as exc:
            return ApplyResult(status="rejected", reason=str(exc))

        action = cmd.action
        port = cmd.port or 0

        # Эскалация: повторный rate_limit для того же IP/порта → блокировка порта
        if action == "rate_limit" and self._has_rate_limit(
            decision.server_id, decision.ip or "", port
        ):
            action = "port_rule"

        if self.observe_mode or not self.auto_enabled:
            self.repo.append_audit(
                "propose",
                details=f"предложено правило {action} для {decision.ip}",
            )
            return ApplyResult(status="proposed", rule_id=None)

        if self._in_cooldown(decision.server_id, decision.ip or ""):
            return ApplyResult(status="ignored", reason="cooldown не истёк")

        if self._interval_not_passed(decision.server_id, decision.ip or ""):
            return ApplyResult(status="ignored", reason="частота обновления правил")

        if action in ("drop", "block_source"):
            if self._count_active_blocks(decision.server_id) >= self.policy.max_concurrent_blocks:
                return ApplyResult(
                    status="rejected", reason="лимит одновременных блокировок"
                )

        try:
            self.backend.apply_rule(
                server_id=decision.server_id,
                ip=decision.ip or "",
                port=port,
                protocol=cmd.protocol,
                action=action,
                expires_at=decision.expires_at,
                rule_id=0,
            )
        except Exception:
            pass

        rule_id = self._persist_rule(
            decision.server_id, decision.ip or "", port,
            cmd.protocol, action, decision.expires_at,
            decision.reason, decision.score,
        )
        # Передаём реальный rule_id в backend, чтобы синхронизация работала
        try:
            self.backend.apply_rule(
                server_id=decision.server_id,
                ip=decision.ip or "",
                port=port,
                protocol=cmd.protocol,
                action=action,
                expires_at=decision.expires_at,
                rule_id=rule_id,
            )
        except Exception:
            pass

        self._touch(decision.server_id, decision.ip or "")
        self.repo.append_audit(
            "apply",
            details=f"применено правило {action} для {decision.ip}",
        )
        return ApplyResult(status="applied", rule_id=rule_id)

    def expire_rules(self, now: Optional[datetime] = None) -> list[int]:
        now = now or self._now()
        iso_now = now.isoformat()
        rows = self.repo.fetch_all(
            "firewall_rules",
            "is_active=1 AND expires_at IS NOT NULL AND expires_at <= ?",
            (iso_now,),
        )
        removed: list[int] = []
        for row in rows:
            rule_id = int(row["id"])
            self.repo.update("firewall_rules", rule_id, is_active=0)
            try:
                self.backend.remove_rule(rule_id)
            except Exception:
                pass
            removed.append(rule_id)
            self.repo.append_audit(
                "expire",
                details=f"правило {rule_id} истекло и снято",
            )
        return removed

    def sync_with_nftables(self) -> dict:
        db_rules = self.repo.get_active_rules()
        backend_rules = self.backend.list_active_rules()
        backend_ids = {int(r.get("rule_id", r.get("id", 0))) for r in backend_rules}
        reapplied = 0
        missing = 0
        for rule in db_rules:
            rule_id = int(rule["id"])
            if rule_id not in backend_ids:
                try:
                    expires_at = rule["expires_at"]
                    dt = None
                    if expires_at:
                        from datetime import datetime as _dt

                        dt = _dt.fromisoformat(expires_at)
                    self.backend.apply_rule(
                        server_id=int(rule["server_id"]),
                        ip=rule["ip"],
                        port=int(rule["port"] or 0),
                        protocol=rule["protocol"],
                        action=rule["action"],
                        expires_at=dt,
                        rule_id=rule_id,
                    )
                    reapplied += 1
                except Exception:
                    missing += 1
        return {"db_rules": len(db_rules), "reapplied": reapplied, "missing": missing}

    def ensure_base_rules(self, server_id: int, ip: str, ports: list[int]) -> None:
        self.backend.ensure_base_rules(server_id, ip, ports)
        self.repo.append_audit(
            "base_rules", details=f"базовые правила для сервера {server_id}"
        )

    def get_active_blocks(self, server_id: int) -> int:
        return self._count_active_blocks(server_id)

    def deactivate_rule(self, rule_id: int) -> bool:
        return self.repo.deactivate_rule(rule_id)

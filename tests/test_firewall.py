"""Тесты модуля firewall: валидация и Rule Manager."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.firewall.policy import ActionType, PolicyProfile, ServerPolicy
from app.firewall.rule_manager import (
    ApplyResult,
    NftablesBackend,
    RuleDecision,
    RuleManager,
)
from app.firewall.validation import (
    FirewallCommand,
    ValidationError,
    validate_command,
    validate_expires_at,
    validate_ip,
    validate_port,
    validate_protocol,
)
from app.storage.models import FirewallRule, ProtectedPort, ProtectedServer
from app.storage.repository import Repository


# ---------------------------------------------------------------------------
# Подделка бэкенда nftables (не требует root / nftables в тестовой среде)
# ---------------------------------------------------------------------------

class FakeBackend(NftablesBackend):
    def __init__(self) -> None:
        self.rules: dict[int, dict] = {}
        self.removed: list[int] = []
        self.base_calls: list[tuple[int, str, list[int]]] = []

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
        self.rules[rule_id] = {
            "server_id": server_id,
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "action": action,
            "expires_at": expires_at,
        }

    def remove_rule(self, rule_id: int) -> None:
        self.removed.append(rule_id)
        self.rules.pop(rule_id, None)

    def list_active_rules(self) -> list[dict]:
        return [dict(v, rule_id=rid) for rid, v in self.rules.items()]

    def ensure_base_rules(
        self, server_id: int, ip: str, ports: list[int]
    ) -> None:
        self.base_calls.append((server_id, ip, list(ports)))


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------

def make_repo() -> Repository:
    repo = Repository(":memory:")
    repo.connect()
    return repo


def make_server(repo: Repository, active: bool = True) -> int:
    server_id = repo.insert(
        "protected_servers",
        ProtectedServer(
            name="test-server",
            ip="10.0.0.1",
            interface="eth0",
            max_pps=1000,
            is_active=active,
            profile=PolicyProfile.CUSTOM.value,
        ),
    )
    repo.insert(
        "protected_ports",
        ProtectedPort(server_id=server_id, port=8080, protocol="tcp"),
    )
    repo.insert(
        "protected_ports",
        ProtectedPort(server_id=server_id, port=9090, protocol="udp"),
    )
    return server_id


def make_policy(**overrides) -> ServerPolicy:
    data = dict(
        profile=PolicyProfile.CUSTOM,
        allowed_actions=set(ActionType),
        max_concurrent_blocks=10,
        cooldown_s=0,
        min_consecutive_violations=1,
        confirmation_window_s=1,
    )
    data.update(overrides)
    return ServerPolicy(**data)


# ---------------------------------------------------------------------------
# Тесты валидации (validation.py)
# ---------------------------------------------------------------------------

class TestValidation:
    def test_validate_ip_valid(self):
        assert validate_ip("10.0.0.1") == "10.0.0.1"
        assert validate_ip("::1") == "::1"
        assert validate_ip("") == ""
        assert validate_ip("any") == "any"

    def test_validate_ip_invalid(self):
        with pytest.raises(ValidationError):
            validate_ip("999.999.999.999")
        with pytest.raises(ValidationError):
            validate_ip("not-an-ip")

    def test_validate_port(self):
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535
        assert validate_port("8080") == 8080
        with pytest.raises(ValidationError):
            validate_port(0)
        with pytest.raises(ValidationError):
            validate_port(65536)
        with pytest.raises(ValidationError):
            validate_port("abc")

    def test_validate_protocol(self):
        assert validate_protocol("tcp") == "tcp"
        assert validate_protocol("UDP") == "udp"
        assert validate_protocol("both") == "both"
        assert validate_protocol("") == "tcp"
        with pytest.raises(ValidationError):
            validate_protocol("icmp")

    def test_validate_expires_at(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        assert validate_expires_at(future) is not None
        assert validate_expires_at(None) is None
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        with pytest.raises(ValidationError):
            validate_expires_at(past)

    def test_validate_command_unknown_action_rejected(self, make_repo=make_repo):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy()
        cmd = FirewallCommand(action="shell-command", server_id=server_id)  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            validate_command(cmd, repo, policy)

    def test_validate_command_server_not_found(self, make_repo=make_repo):
        repo = make_repo()
        policy = make_policy()
        cmd = FirewallCommand(action=ActionType.DROP, server_id=9999)
        with pytest.raises(ValidationError):
            validate_command(cmd, repo, policy)

    def test_validate_command_action_not_allowed(self, make_repo=make_repo):
        repo = make_repo()
        server_id = make_server(repo)
        policy = ServerPolicy.for_profile(PolicyProfile.WEB)  # DROP не разрешён
        cmd = FirewallCommand(action=ActionType.DROP, server_id=server_id)
        with pytest.raises(ValidationError):
            validate_command(cmd, repo, policy)

    def test_validate_command_port_not_protected(self, make_repo=make_repo):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy()
        cmd = FirewallCommand(
            action=ActionType.DROP, server_id=server_id, port=12345, protocol="tcp"
        )
        with pytest.raises(ValidationError):
            validate_command(cmd, repo, policy)

    def test_validate_command_ok(self, make_repo=make_repo):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        cmd = FirewallCommand(
            action=ActionType.RATE_LIMIT,
            server_id=server_id,
            ip="10.0.0.1",
            port=8080,
            protocol="tcp",
            expires_at=future,
            reason="test",
        )
        validated = validate_command(cmd, repo, policy)
        assert validated.action == ActionType.RATE_LIMIT
        assert validated.server_id == server_id
        assert validated.port == 8080
        assert validated.protocol == "tcp"
        assert validated.ip == "10.0.0.1"
        assert validated.reason == "test"


# ---------------------------------------------------------------------------
# Тесты Rule Manager (rule_manager.py)
# ---------------------------------------------------------------------------

class TestRuleManager:
    def _manager(self, repo, policy=None, backend=None, **kwargs):
        if policy is None:
            policy = make_policy()
        return RuleManager(repo, policy, backend, **kwargs)

    def test_observe_mode_proposes_only(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()
        mgr = self._manager(repo, backend=backend, observe_mode=True)

        decision = RuleDecision(
            action=ActionType.DROP,
            server_id=server_id,
            ip="1.2.3.4",
            port=8080,
            reason="test",
        )
        result = mgr.apply_decision(decision)

        assert result.status == "proposed"
        assert result.rule_id is None
        assert backend.rules == {}
        # правил в firewall_rules не должно быть применено (только аудит)
        rules = repo.get_active_rules(server_id)
        assert rules == []

    def test_auto_disabled_proposes_only(self):
        repo = make_repo()
        server_id = make_server(repo)
        mgr = self._manager(repo, auto_enabled=False)
        decision = RuleDecision(
            action=ActionType.RATE_LIMIT, server_id=server_id, reason="test"
        )
        result = mgr.apply_decision(decision)
        assert result.status == "proposed"

    def test_apply_success_persists_and_applies(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()
        policy = make_policy(cooldown_s=0)
        mgr = self._manager(repo, policy=policy, backend=backend)

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        decision = RuleDecision(
            action=ActionType.RATE_LIMIT,
            server_id=server_id,
            ip="10.0.0.1",
            port=8080,
            protocol="tcp",
            expires_at=future,
            reason="high load",
            score=5.0,
        )
        result = mgr.apply_decision(decision)

        assert result.status == "applied"
        assert result.rule_id is not None
        assert result.rule_id in backend.rules
        assert backend.rules[result.rule_id]["action"] == "rate_limit"

        rules = repo.get_active_rules(server_id)
        assert len(rules) == 1
        assert rules[0]["action"] == "rate_limit"
        assert rules[0]["is_active"] == 1

        audits = repo.fetch_all("audit_logs")
        assert any(a["action"] == "apply" for a in audits)

    def test_web_profile_rejects_drop(self):
        repo = make_repo()
        server_id = make_server(repo)
        policy = ServerPolicy.for_profile(PolicyProfile.WEB)
        mgr = self._manager(repo, policy=policy)

        decision = RuleDecision(
            action=ActionType.DROP, server_id=server_id, ip="1.2.3.4", reason="x"
        )
        result = mgr.apply_decision(decision)
        assert result.status == "rejected"

    def test_whitelist_ignored(self):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy(cooldown_s=0)
        policy.whitelist.add("1.2.3.4")
        mgr = RuleManager(
            repo, policy, observe_mode=False, auto_enabled=True,
            min_update_interval_s=0,
        )

        decision = RuleDecision(
            action=ActionType.DROP,
            server_id=server_id,
            ip="1.2.3.4",
            port=8080,
            protocol="tcp",
            reason="x",
        )
        result = mgr.apply_decision(decision)
        assert result.status == "ignored"
        assert result.reason == "адрес в белом списке"
        assert repo.get_active_rules(server_id) == []

    def test_cooldown_ignores_repeat(self):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy(cooldown_s=3600)
        mgr = RuleManager(
            repo, policy, min_update_interval_s=0,
        )

        decision = RuleDecision(
            action=ActionType.RATE_LIMIT,
            server_id=server_id,
            ip="1.2.3.4",
            port=8080,
            protocol="tcp",
            reason="x",
        )
        r1 = mgr.apply_decision(decision)
        assert r1.status == "applied"
        r2 = mgr.apply_decision(decision)
        assert r2.status == "ignored"
        assert r2.reason == "cooldown не истёк"

    def test_update_rate_limit_ignores_repeat(self):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy(cooldown_s=0)
        mgr = RuleManager(
            repo, policy, min_update_interval_s=3600,
        )

        decision = RuleDecision(
            action=ActionType.RATE_LIMIT,
            server_id=server_id,
            ip="1.2.3.4",
            port=8080,
            protocol="tcp",
            reason="x",
        )
        r1 = mgr.apply_decision(decision)
        assert r1.status == "applied"
        r2 = mgr.apply_decision(decision)
        assert r2.status == "ignored"
        assert "частота обновления" in r2.reason

    def test_concurrent_blocks_limit(self):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy(cooldown_s=0, max_concurrent_blocks=1)
        mgr = RuleManager(
            repo, policy, min_update_interval_s=0,
        )

        d1 = RuleDecision(
            action=ActionType.DROP,
            server_id=server_id,
            ip="1.2.3.4",
            port=8080,
            protocol="tcp",
            reason="a",
        )
        r1 = mgr.apply_decision(d1)
        assert r1.status == "applied"
        assert mgr.get_active_blocks(server_id) == 1

        d2 = RuleDecision(
            action=ActionType.DROP,
            server_id=server_id,
            ip="5.6.7.8",
            port=8080,
            protocol="tcp",
            reason="b",
        )
        r2 = mgr.apply_decision(d2)
        assert r2.status == "rejected"
        assert "лимит одновременных блокировок" in r2.reason

    def test_expire_rules(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()
        mgr = self._manager(repo, backend=backend)

        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        rule_id = repo.insert(
            "firewall_rules",
            FirewallRule(
                server_id=server_id,
                ip="1.2.3.4",
                port=8080,
                protocol="tcp",
                action="drop",
                expires_at=past,
                is_active=True,
            ),
        )
        backend.apply_rule(
            server_id=server_id,
            ip="1.2.3.4",
            port=8080,
            protocol="tcp",
            action="drop",
            expires_at=past,
            rule_id=rule_id,
        )

        removed = mgr.expire_rules(now=datetime.now(timezone.utc))
        assert removed == [rule_id]
        assert rule_id in backend.removed
        row = repo.fetch_one("firewall_rules", "id=?", (rule_id,))
        assert row["is_active"] == 0

    def test_sync_with_nftables_reapplies_missing(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        rule_id = repo.insert(
            "firewall_rules",
            FirewallRule(
                server_id=server_id,
                ip="10.0.0.1",
                port=8080,
                protocol="tcp",
                action="rate_limit",
                expires_at=future,
                is_active=True,
            ),
        )

        # В nftables правила нет (как после перезапуска Python).
        mgr = self._manager(repo, backend=backend)
        stats = mgr.sync_with_nftables()

        assert stats["db_rules"] == 1
        assert stats["reapplied"] == 1
        assert stats["missing"] == 0
        assert rule_id in backend.rules

    def test_ensure_base_rules(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()
        mgr = self._manager(repo, backend=backend)

        mgr.ensure_base_rules(server_id, "10.0.0.1", [8080, 9090])
        assert backend.base_calls == [(server_id, "10.0.0.1", [8080, 9090])]
        audits = repo.fetch_all("audit_logs")
        assert any(a["action"] == "base_rules" for a in audits)

    def test_escalation(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()
        policy = make_policy(cooldown_s=0)
        mgr = RuleManager(
            repo, policy, backend, min_update_interval_s=0,
        )

        ip = "1.2.3.4"
        d1 = RuleDecision(
            action=ActionType.RATE_LIMIT,
            server_id=server_id,
            ip=ip,
            port=8080,
            protocol="tcp",
            reason="x",
        )
        r1 = mgr.apply_decision(d1)
        assert r1.status == "applied"

        # Повтор того же действия для той же цели → постепенное усиление.
        d2 = RuleDecision(
            action=ActionType.RATE_LIMIT,
            server_id=server_id,
            ip=ip,
            port=8080,
            protocol="tcp",
            reason="x",
        )
        r2 = mgr.apply_decision(d2)
        assert r2.status == "applied"
        assert backend.rules[r2.rule_id]["action"] == "port_rule"

    def test_rejected_validation_not_applied(self):
        repo = make_repo()
        server_id = make_server(repo)
        backend = FakeBackend()
        mgr = self._manager(repo, backend=backend)

        # Порт не защищён сервером.
        decision = RuleDecision(
            action=ActionType.DROP,
            server_id=server_id,
            port=12345,
            reason="x",
        )
        result = mgr.apply_decision(decision)
        assert result.status == "rejected"
        assert backend.rules == {}

    def test_set_observe_and_auto(self):
        repo = make_repo()
        server_id = make_server(repo)
        policy = make_policy()
        mgr = self._manager(repo, policy=policy)

        mgr.set_auto_enabled(False)
        assert mgr.auto_enabled is False
        mgr.set_observe_mode(True)
        assert mgr.observe_mode is True
        audits = repo.fetch_all("audit_logs")
        assert any(a["action"] == "config" for a in audits)

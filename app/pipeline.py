from __future__ import annotations

import logging
import signal
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.collector.sources import MetricCollector, MetricSnapshot
from app.collector.interfaces import InterfaceSource
from app.collector.nftables import NftablesSource
from app.collector.conntrack import ConntrackSource
from app.collector.conntrack_top import ConntrackTopSource
from app.collector.system_metrics import SystemMetricsSource
from app.detector.scoring import Detector, Decision, ScoringScale
from app.detector.thresholds import ThresholdDetector, ThresholdRule
from app.firewall.policy import PolicyProfile, ServerPolicy
from app.firewall.rule_manager import RuleDecision, RuleManager, NftablesBackend
from app.storage.factory import get_config_storage
from app.storage.repository import utcnow

log = logging.getLogger("netshield.pipeline")


class ProtectionPipeline:
    """Основной конвейер защиты: сбор метрик -> обнаружение аномалий -> применение правил.

    Запускается как отдельный поток. Не участвует в пересылке пакетов
    (это делает ядро Linux), а работает с агрегированными метриками.
    """

    def __init__(
        self,
        interval_sec: float = 1.0,
        observation_mode: bool = True,
        auto_actions: bool = False,
    ) -> None:
        self.interval_sec = interval_sec
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.repo = get_config_storage()

        self.collector = MetricCollector(interval_sec=interval_sec)
        self.detectors: dict[int, Detector] = {}
        self.rule_managers: dict[int, RuleManager] = {}
        self.server_configs: dict[int, dict] = {}

        self.observation_mode = observation_mode
        self.auto_actions = auto_actions

        self._last_rule_sync: Optional[float] = None
        self._rule_sync_interval = 30.0

    # ------------------------------------------------------------------ setup

    def load_servers(self) -> None:
        """Загружает конфигурацию защищаемых серверов из БД."""
        servers = self.repo.list_servers(include_ports=True, active_only=True)
        self.server_configs = {s["id"]: s for s in servers}

        for server in servers:
            sid = server["id"]
            ports = server.get("ports", [])

            rule = ThresholdRule(
                max_pps=int(server.get("max_pps") or 0),
                max_bps=int(server.get("max_bps") or 0),
                max_new_tcp_per_s=int(server.get("max_new_tcp_per_s") or 0),
                max_udp_pps=int(server.get("max_udp_pps") or 0),
                max_new_sources=int(server.get("max_new_sources") or 0),
                max_connections=int(server.get("max_connections") or 0),
            )

            profile = PolicyProfile(server.get("profile", "custom"))
            policy = ServerPolicy.for_profile(profile)

            detector = Detector(
                server_id=sid,
                threshold_detector=ThresholdDetector(rule),
                confirmation_count=3,
                cooldown_seconds=int(self.repo.get_setting("cooldown_seconds", "60")),
            )
            detector.set_observation_mode(self.observation_mode)

            backend = NftablesBackend()
            mgr = RuleManager(
                repo=self.repo,
                policy=policy,
                backend=backend,
                observe_mode=self.observation_mode,
                auto_enabled=self.auto_actions,
                min_update_interval_s=5,
            )

            self.detectors[sid] = detector
            self.rule_managers[sid] = mgr

            # Источники метрик для сервера
            iface = server.get("interface") or "eth0"
            self.collector.add_source(InterfaceSource(server_id=sid, interface=iface))
            self.collector.add_source(NftablesSource(server_id=sid))
            self.collector.add_source(ConntrackSource(server_id=sid))
            self.collector.add_source(ConntrackTopSource(server_id=sid))
            self.collector.add_source(SystemMetricsSource(server_id=sid))

            log.info(
                "Сервер %s (%s) добавлен в конвейер: профиль=%s, порты=%s",
                sid,
                server.get("ip", "?"),
                profile.value,
                [p.get("port") for p in ports],
            )

    def reload_config(self) -> None:
        """Перезагружает конфигурацию серверов (вызывается по API)."""
        self.detectors.clear()
        self.rule_managers.clear()
        self.server_configs.clear()
        self.collector = MetricCollector(interval_sec=self.interval_sec)
        self.load_servers()
        log.info("Конфигурация серверов перезагружена")

    # ---------------------------------------------------------------- processing

    def _process_snapshot(self, snap: MetricSnapshot) -> None:
        sid = snap.server_id
        if sid not in self.detectors:
            return

        detector = self.detectors[sid]
        now = time.time()

        decision: Decision = detector.evaluate(
            in_pps=snap.in_pps,
            in_bps=snap.in_bps,
            tcp_new=snap.tcp_new,
            udp_pps=snap.udp_pps,
            new_sources=snap.new_sources,
            connections=snap.conntrack_count,
            now=now,
            top_sources=snap.top_sources,
        )

        # Сохраняем событие, если есть аномалия
        if decision.score > 0:
            self._save_event(sid, decision, snap)

        # Применяем защитное правило (если не observation mode и auto_actions)
        if decision.action not in ("none", "alert") or decision.score >= 4:
            self._apply_decision(sid, decision, snap)

    def _save_event(self, sid: int, decision: Decision, snap: MetricSnapshot) -> None:
        from app.storage.models import AnomalyEvent

        severity = ScoringScale.level(decision.score)
        event_type = self._classify_event(decision)

        event = AnomalyEvent(
            server_id=sid,
            timestamp=utcnow(),
            event_type=event_type,
            score=float(decision.score),
            severity=severity,
            details=decision.details or "",
            action_status="proposed" if self.observation_mode else "applied",
            protocol="",
        )
        try:
            self.repo.save_anomaly_event(event)
        except Exception as exc:
            log.exception("Не удалось сохранить событие аномалии: %s", exc)

    def _classify_event(self, decision: Decision) -> str:
        reasons = " ".join(decision.reasons).lower()
        if "udp" in reasons:
            return "udp_flood"
        if "tcp_new" in reasons or "syn" in reasons:
            return "syn_flood"
        if "new_sources" in reasons:
            return "port_scan"
        return "anomaly"

    def _apply_decision(self, sid: int, decision: Decision, snap: MetricSnapshot) -> None:
        mgr = self.rule_managers.get(sid)
        if mgr is None:
            return

        server = self.server_configs.get(sid, {})
        ports = [int(p.get("port", 0)) for p in server.get("ports", [])]
        port = ports[0] if ports else 0
        protocol = "tcp"

        # Какие IP блокировать — из детектора (топ источников коннектов)
        target_ips = list(decision.block_ips) if decision.block_ips else [server.get("ip", "")]

        for ip in target_ips:
            if not ip:
                continue

            rule_decision = RuleDecision(
                action=decision.action,
                server_id=sid,
                ip=ip,
                port=port,
                protocol=protocol,
                reason=decision.details or "аномалия",
                score=decision.score,
                ttl_seconds=decision.ttl_seconds,
                expires_at=(
                    datetime.now(timezone.utc) + timedelta(seconds=decision.ttl_seconds)
                    if decision.ttl_seconds > 0
                    else None
                ),
            )

            try:
                result = mgr.apply_decision(rule_decision)
                if result.status in ("applied", "proposed"):
                    log.info(
                        "Сервер %d: правило %s для IP %s — %s",
                        sid,
                        decision.action,
                        ip,
                        result.status,
                    )
                elif result.status == "rejected":
                    log.warning(
                        "Сервер %d: правило для IP %s отвергнуто: %s", sid, ip, result.reason
                    )
            except Exception as exc:
                log.exception(
                    "Ошибка применения правила для сервера %d IP %s: %s", sid, ip, exc
                )

    def _sync_rules(self) -> None:
        """Перепроверяет и применяет базовые правила nftables для всех серверов."""
        now = time.time()
        if (
            self._last_rule_sync is not None
            and (now - self._last_rule_sync) < self._rule_sync_interval
        ):
            return
        self._last_rule_sync = now

        for sid, mgr in self.rule_managers.items():
            server = self.server_configs.get(sid, {})
            ip = server.get("ip", "")
            ports = [int(p.get("port", 0)) for p in server.get("ports", [])]
            if ip and ports:
                try:
                    mgr.ensure_base_rules(sid, ip, ports)
                except Exception as exc:
                    log.warning("ensure_base_rules для сервера %d: %s", sid, exc)

        try:
            mgr = next(iter(self.rule_managers.values()), None)
            if mgr is not None:
                mgr.expire_rules(now=utcnow())
        except Exception as exc:
            log.warning("expire_rules: %s", exc)

    def _collect_callback(self, snaps: list[MetricSnapshot]) -> None:
        for snap in snaps:
            if snap.error:
                log.warning("Ошибка сбора метрик: %s", snap.error)
                continue
            self._process_snapshot(snap)
        self._sync_rules()

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self.load_servers()
        self._thread = threading.Thread(
            target=self._run_loop, name="netshield-pipeline", daemon=True
        )
        self._thread.start()
        log.info(
            "Конвейер защиты запущен (interval=%.1fs, observation=%s, auto=%s)",
            self.interval_sec,
            self.observation_mode,
            self.auto_actions,
        )

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                snaps = self.collector.collect_once()
                self._collect_callback(snaps)
            except Exception:
                log.exception("Ошибка в цикле сбора метрик")
            self._stop_event.wait(self.interval_sec)

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self.collector.stop()
        log.info("Конвейер защиты остановлен")


# Глобальный экземпляр конвейера (запускается из main.py lifespan при необходимости)
pipeline: Optional[ProtectionPipeline] = None

"""Detector: фиксированные пороговые значения (алгоритм A)."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["ThresholdRule", "ThresholdResult", "ThresholdDetector"]


@dataclass
class ThresholdRule:
    """Порог для одного сервера. Значения настраиваемые."""

    max_pps: int = 0          # максимум PPS (входящий)
    max_bps: int = 0          # максимум входящего трафика (бит/с)
    max_new_tcp_per_s: int = 0  # новых TCP-соединений в секунду
    max_udp_pps: int = 0      # UDP пакетов в секунду
    max_new_sources: int = 0  # новых источников за интервал
    max_connections: int = 0  # предельное число соединений

    # веса баллов за превышение (настраиваемые)
    weight_tcp: int = 2
    weight_udp: int = 2
    weight_traffic: int = 3
    weight_sources: int = 2
    weight_connections: int = 2


@dataclass
class ThresholdResult:
    exceeded: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)


class ThresholdDetector:
    """
    Алгоритм A: фиксированные пороги.
    Начисляет баллы за превышение каждого порога.
    """

    def __init__(self, rule: ThresholdRule | None = None) -> None:
        self.rule = rule or ThresholdRule()

    def check(self, in_pps: float, in_bps: float, tcp_new: int,
              udp_pps: float, new_sources: int, connections: int) -> ThresholdResult:
        rule = self.rule
        result = ThresholdResult()

        if rule.max_pps > 0 and in_pps > rule.max_pps:
            result.exceeded = True
            result.score += rule.weight_traffic
            result.reasons.append(f"in_pps {in_pps:.0f} > {rule.max_pps}")

        if rule.max_bps > 0 and in_bps > rule.max_bps:
            result.exceeded = True
            result.score += rule.weight_traffic
            result.reasons.append(f"in_bps {in_bps:.0f} > {rule.max_bps}")

        if rule.max_new_tcp_per_s > 0 and tcp_new > rule.max_new_tcp_per_s:
            result.exceeded = True
            result.score += rule.weight_tcp
            result.reasons.append(f"tcp_new {tcp_new} > {rule.max_new_tcp_per_s}")

        if rule.max_udp_pps > 0 and udp_pps > rule.max_udp_pps:
            result.exceeded = True
            result.score += rule.weight_udp
            result.reasons.append(f"udp_pps {udp_pps:.0f} > {rule.max_udp_pps}")

        if rule.max_new_sources > 0 and new_sources > rule.max_new_sources:
            result.exceeded = True
            result.score += rule.weight_sources
            result.reasons.append(f"new_sources {new_sources} > {rule.max_new_sources}")

        if rule.max_connections > 0 and connections > rule.max_connections:
            result.exceeded = True
            result.score += rule.weight_connections
            result.reasons.append(f"connections {connections} > {rule.max_connections}")

        return result

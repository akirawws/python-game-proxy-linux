from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.detector.ewma import EWMADetector
from app.detector.statistics import StatisticsDetector
from app.detector.thresholds import ThresholdDetector, ThresholdResult
from app.detector.algorithm_d import BurstDetector

__all__ = [
    "Decision",
    "ScoringScale",
    "Detector",
]

@dataclass
class Decision:

    server_id: int
    level: str
    score: int
    reasons: list[str] = field(default_factory=list)
    action: str = "none"
    ttl_seconds: int = 0
    details: str = ""
    block_ips: list[str] = field(default_factory=list)

class ScoringScale:

    @staticmethod
    def level(score: int) -> str:
        if score <= 1:
            return "normal"
        if score <= 3:
            return "low"
        if score <= 5:
            return "medium"
        return "high"

class Detector:

    def __init__(
        self,
        server_id: int,
        threshold_detector: Optional[ThresholdDetector] = None,
        ewma: Optional[EWMADetector] = None,
        statistics: Optional[StatisticsDetector] = None,
        burst: Optional[BurstDetector] = None,
        confirmation_count: int = 2,
        cooldown_seconds: int = 30,
    ) -> None:
        self.server_id = server_id
        self.thresholds = threshold_detector or ThresholdDetector()
        self.ewma = ewma or EWMADetector()
        self.statistics = statistics or StatisticsDetector()
        self.burst = burst or BurstDetector()
        self.confirmation_count = confirmation_count
        self.cooldown_seconds = cooldown_seconds

        self._consecutive_exceeds = 0
        self._last_event_time: float = 0.0
        self._observation_mode = True

    def set_observation_mode(self, enabled: bool) -> None:
        self._observation_mode = enabled

    def evaluate(
        self,
        in_pps: float,
        in_bps: float,
        tcp_new: int,
        udp_pps: float,
        new_sources: int,
        connections: int,
        now: float,
        top_sources: list[tuple[str, int]] = (),
    ) -> Decision:

        thr_result: ThresholdResult = self.thresholds.check(
            in_pps, in_bps, tcp_new, udp_pps, new_sources, connections
        )

        ewma_exceed, ewma_ratio = self.ewma.check(in_pps)
        self.ewma.update(in_pps, is_attack=thr_result.exceeded)

        stat_exceed, z_score = self.statistics.check(in_pps)
        self.statistics.add(in_pps)

        burst_exceed, burst_ratio = self.burst.check(in_pps)
        self.burst.add(in_pps)

        score = thr_result.score
        reasons = list(thr_result.reasons)

        if ewma_exceed:
            score += 2
            reasons.append(f"ewma deviation x{ewma_ratio:.1f}")
        if stat_exceed:
            score += 2
            reasons.append(f"stat z-score {z_score:.1f}")
        if burst_exceed:
            score += 2
            reasons.append(f"burst x{burst_ratio:.1f}")

        if score > 0:
            self._consecutive_exceeds += 1
        else:
            self._consecutive_exceeds = 0

        confirmed = self._consecutive_exceeds >= self.confirmation_count

        in_cooldown = (now - self._last_event_time) < self.cooldown_seconds

        level = ScoringScale.level(score)

        action = "none"
        ttl_seconds = 0
        block_ips: list[str] = []

        if confirmed and not in_cooldown:
            self._last_event_time = now
            if self._observation_mode:
                action = "alert"
                ttl_seconds = 0
            else:
                if level == "high":
                    action = "drop"
                    ttl_seconds = 300
                elif level == "medium":
                    action = "limit"
                    ttl_seconds = 120
                elif level == "low":
                    action = "alert"
                    ttl_seconds = 0

            if action in ("drop", "limit") and top_sources:
                block_ips = [ip for ip, _ in top_sources]

        return Decision(
            server_id=self.server_id,
            level=level,
            score=score,
            reasons=reasons,
            action=action,
            ttl_seconds=ttl_seconds,
            details="; ".join(reasons) if reasons else "норма",
            block_ips=block_ips,
        )

"""Detector: оценка балла риска и объединение алгоритмов."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.detector.ewma import EWMADetector
from app.detector.statistics import StatisticsDetector
from app.detector.thresholds import ThresholdDetector, ThresholdResult

__all__ = [
    "Decision",
    "ScoringScale",
    "Detector",
]


@dataclass
class Decision:
    """Структурированное решение для Rule Manager."""

    server_id: int
    level: str  # normal / low / medium / high
    score: int
    reasons: list[str] = field(default_factory=list)
    action: str = "none"  # none / alert / limit / drop
    ttl_seconds: int = 0
    details: str = ""


class ScoringScale:
    """Шкала: 0–1 нормальный, 2–3 низкий, 4–5 средний, 6+ высокий."""

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
    """
    Объединяет алгоритмы A (пороги), B (EWMA), C (статистика) в общий балл.
    Защита от ложных срабатываний: минимальное число последовательных
    превышений, время подтверждения, cooldown, постепенное усиление.
    Режим наблюдения: фиксировать аномалии без изменения фильтрации.
    """

    def __init__(
        self,
        server_id: int,
        threshold_detector: Optional[ThresholdDetector] = None,
        ewma: Optional[EWMADetector] = None,
        statistics: Optional[StatisticsDetector] = None,
        confirmation_count: int = 2,
        cooldown_seconds: int = 30,
    ) -> None:
        self.server_id = server_id
        self.thresholds = threshold_detector or ThresholdDetector()
        self.ewma = ewma or EWMADetector()
        self.statistics = statistics or StatisticsDetector()
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
    ) -> Decision:
        """
        Вычислить балл риска и сформировать Decision.
        """

        # --- Алгоритм A: фиксированные пороги ---
        thr_result: ThresholdResult = self.thresholds.check(
            in_pps, in_bps, tcp_new, udp_pps, new_sources, connections
        )

        # --- Алгоритм B: EWMA ---
        ewma_exceed, ewma_ratio = self.ewma.check(in_pps)
        self.ewma.update(in_pps, is_attack=thr_result.exceeded)

        # --- Алгоритм C: статистика ---
        stat_exceed, z_score = self.statistics.check(in_pps)
        self.statistics.add(in_pps)

        # --- Начисление баллов ---
        score = thr_result.score
        reasons = list(thr_result.reasons)

        if ewma_exceed:
            score += 2
            reasons.append(f"ewma deviation x{ewma_ratio:.1f}")
        if stat_exceed:
            score += 2
            reasons.append(f"stat z-score {z_score:.1f}")

        # --- Защита от ложных срабатываний ---
        if score > 0:
            self._consecutive_exceeds += 1
        else:
            self._consecutive_exceeds = 0

        confirmed = self._consecutive_exceeds >= self.confirmation_count

        in_cooldown = (now - self._last_event_time) < self.cooldown_seconds

        level = ScoringScale.level(score)

        # --- Формирование действия ---
        action = "none"
        ttl_seconds = 0

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

        return Decision(
            server_id=self.server_id,
            level=level,
            score=score,
            reasons=reasons,
            action=action,
            ttl_seconds=ttl_seconds,
            details="; ".join(reasons) if reasons else "норма",
        )

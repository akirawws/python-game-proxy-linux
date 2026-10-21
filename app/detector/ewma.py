"""Detector: экспоненциальное скользящее среднее (алгоритм B)."""

from __future__ import annotations

__all__ = ["EWMADetector"]


class EWMADetector:
    """
    EWMA-базовая линия: baseline = alpha * value + (1 - alpha) * baseline.
    Отклонение в N раз от базовой линии даёт балл.
    Заморозка базовой линии во время атаки, чтобы атака не стала «нормой».
    """

    def __init__(
        self,
        alpha: float = 0.1,
        deviation_factor: float = 3.0,
        min_baseline: float = 1.0,
    ) -> None:
        self.alpha = alpha
        self.deviation_factor = deviation_factor
        self.min_baseline = min_baseline
        self._baseline: float | None = None
        self._frozen = False

    def update(self, value: float, is_attack: bool = False) -> float:
        """Обновить базовую линию. Если is_attack — не обновлять (заморозка)."""
        if self._frozen or is_attack:
            return self._baseline if self._baseline is not None else value

        if self._baseline is None:
            self._baseline = max(value, self.min_baseline)
        else:
            self._baseline = (
                self.alpha * value + (1.0 - self.alpha) * self._baseline
            )
            self._baseline = max(self._baseline, self.min_baseline)
        return self._baseline

    def freeze(self) -> None:
        self._frozen = True

    def unfreeze(self) -> None:
        self._frozen = False

    def check(self, value: float) -> tuple[bool, float]:
        """
        Проверить, превышает ли значение базовую линию в deviation_factor раз.
        Возвращает (превышение, коэффициент отклонения).
        """
        if self._baseline is None or self._baseline <= 0:
            return False, 0.0
        ratio = value / self._baseline
        return ratio > self.deviation_factor, ratio

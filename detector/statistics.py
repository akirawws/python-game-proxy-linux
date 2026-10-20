"""Detector: статистическое отклонение от нормы (алгоритм C)."""

from __future__ import annotations

import statistics as _statistics
from collections import deque

__all__ = ["StatisticsDetector"]


class StatisticsDetector:
    """
    Алгоритм C: среднее μ и σ по предыдущему окну (без текущего измерения).
    Медиана и MAD для пиковых метрик.
    """

    def __init__(self, window_size: int = 60, sigma_factor: float = 3.0) -> None:
        self.window_size = window_size
        self.sigma_factor = sigma_factor
        self._history: deque[float] = deque(maxlen=window_size)

    def add(self, value: float) -> None:
        self._history.append(value)

    def check(self, value: float) -> tuple[bool, float]:
        """
        Сравнить значение с базовой линией по предыдущему окну.
        Возвращает (аномалия, z-оценка).
        Базовая линия не включает текущее значение.
        """
        if len(self._history) < 5:
            return False, 0.0

        data = list(self._history)
        mean = _statistics.mean(data)
        try:
            stdev = _statistics.stdev(data)
        except _statistics.StatisticsError:
            stdev = 0.0

        if stdev == 0:
            # все значения одинаковые — любое отклонение от них — аномалия
            return value != mean, 1.0 if value != mean else 0.0

        z_score = abs(value - mean) / stdev
        return z_score > self.sigma_factor, z_score

    def median_mad_check(self, value: float, mad_factor: float = 3.0) -> tuple[bool, float]:
        """
        Медиана и MAD для пиковых метрик. Устойчивы к выбросам в истории.
        """
        if len(self._history) < 5:
            return False, 0.0

        data = sorted(self._history)
        n = len(data)
        median = data[n // 2] if n % 2 else (data[n // 2 - 1] + data[n // 2]) / 2
        abs_dev = [abs(x - median) for x in data]
        abs_dev.sort()
        mad = abs_dev[n // 2] if n % 2 else (abs_dev[n // 2 - 1] + abs_dev[n // 2]) / 2

        if mad == 0:
            return value != median, 1.0 if value != median else 0.0

        score = abs(value - median) / mad
        return score > mad_factor, score

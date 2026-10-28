from __future__ import annotations

from collections import deque

__all__ = ["BurstDetector"]


class BurstDetector:
    def __init__(
        self,
        window_short: int = 5,
        window_long: int = 30,
        factor: float = 3.0,
    ) -> None:
        self.window_short = window_short
        self.window_long = window_long
        self.factor = factor
        self._history: deque[float] = deque(maxlen=window_long)

    def add(self, value: float) -> None:
        self._history.append(value)

    def check(self, value: float) -> tuple[bool, float]:
        if len(self._history) < self.window_long:
            return False, 0.0

        data = list(self._history)
        baseline = sum(data[:-self.window_short]) / max(
            len(data) - self.window_short, 1
        )
        recent = sum(data[-self.window_short:]) / self.window_short

        if baseline <= 0:
            return recent > 0, 1.0 if recent > 0 else 0.0

        ratio = recent / baseline
        return ratio > self.factor, ratio

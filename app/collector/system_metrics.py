from __future__ import annotations

import time
from typing import Optional

from app.collector.sources import MetricSnapshot, MetricSource

__all__ = ["SystemMetricsSource"]


class SystemMetricsSource(MetricSource):
    """Сбор системных метрик Linux: загрузка CPU, память, загрузка интерфейсов.

    Читает значения из /proc и /sys. Не требует root-прав для чтения.
    """

    CPU_STAT_PATH = "/proc/stat"
    MEMINFO_PATH = "/proc/meminfo"

    def __init__(self, server_id: int) -> None:
        self.server_id = server_id
        self._prev_cpu: Optional[tuple[int, int]] = None
        self._prev_cpu_time: Optional[float] = None

    def name(self) -> str:
        return "system"

    def _read_cpu(self) -> Optional[tuple[int, int]]:
        """Возвращает (total_ticks, idle_ticks)."""
        try:
            with open(self.CPU_STAT_PATH, "r", encoding="ascii") as fh:
                line = fh.readline()
        except (FileNotFoundError, PermissionError, OSError):
            return None
        parts = line.split()
        if len(parts) < 5 or parts[0] != "cpu":
            return None
        values = [int(x) for x in parts[1:]]
        total = sum(values)
        idle = values[3] if len(values) > 3 else 0
        return total, idle

    def read(self) -> MetricSnapshot:
        now = time.time()
        cpu = self._read_cpu()
        cpu_percent = 0.0
        if cpu is not None:
            if self._prev_cpu is not None and self._prev_cpu_time is not None:
                dt = now - self._prev_cpu_time
                if dt > 0:
                    total_delta = cpu[0] - self._prev_cpu[0]
                    idle_delta = cpu[1] - self._prev_cpu[1]
                    if total_delta > 0:
                        cpu_percent = max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0))
            self._prev_cpu = cpu
            self._prev_cpu_time = now

        mem_total = 0
        mem_available = 0
        try:
            with open(self.MEMINFO_PATH, "r", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        mem_total = int(line.split()[1]) * 1024
                    elif line.startswith("MemAvailable:"):
                        mem_available = int(line.split()[1]) * 1024
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            pass
        mem_percent = 0.0
        if mem_total > 0:
            mem_percent = max(0.0, min(100.0, (1.0 - mem_available / mem_total) * 100.0))

        return MetricSnapshot(
            server_id=self.server_id,
            timestamp=now,
            cpu_percent=cpu_percent,
            mem_percent=mem_percent,
        )

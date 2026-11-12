from __future__ import annotations

from typing import Optional

from app.collector.sources import MetricSnapshot, MetricSource

__all__ = ["ConntrackTopSource"]


class ConntrackTopSource(MetricSource):
    """Читает /proc/net/nf_conntrack и возвращает топ исходных IP по числу соединений."""

    CONNTRACK_PATH = "/proc/net/nf_conntrack"

    def __init__(self, server_id: int, top_n: int = 5) -> None:
        self.server_id = server_id
        self.top_n = top_n

    def name(self) -> str:
        return "conntrack_top"

    def _extract_src(self, line: str) -> Optional[str]:
        for part in line.split():
            if part.startswith("src="):
                return part.split("=", 1)[1]
        return None

    def read(self) -> MetricSnapshot:
        counts: dict[str, int] = {}
        try:
            with open(self.CONNTRACK_PATH, "r", encoding="ascii", errors="ignore") as fh:
                for line in fh:
                    src = self._extract_src(line)
                    if src:
                        counts[src] = counts.get(src, 0) + 1
        except FileNotFoundError:
            return MetricSnapshot(
                server_id=self.server_id,
                timestamp=0.0,
                error="nf_conntrack not available",
            )
        except PermissionError:
            return MetricSnapshot(
                server_id=self.server_id,
                timestamp=0.0,
                error="nf_conntrack permission denied",
            )

        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[: self.top_n]
        return MetricSnapshot(
            server_id=self.server_id,
            timestamp=0.0,
            conntrack_count=sum(counts.values()),
            top_sources=[(ip, cnt) for ip, cnt in top],
        )

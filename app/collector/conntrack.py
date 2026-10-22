from __future__ import annotations

from app.collector.sources import MetricSnapshot, MetricSource

__all__ = ["ConntrackSource"]


class ConntrackSource(MetricSource):

    COUNT_PATH = "/proc/sys/net/netfilter/nf_conntrack_count"
    MAX_PATH = "/proc/sys/net/netfilter/nf_conntrack_max"

    def __init__(self, server_id: int) -> None:
        self.server_id = server_id

    def name(self) -> str:
        return "conntrack"

    def _read_int(self, path: str) -> int:
        try:
            with open(path, "r", encoding="ascii") as fh:
                return int(fh.read().strip())
        except (FileNotFoundError, ValueError, PermissionError):
            return 0

    def read(self) -> MetricSnapshot:
        count = self._read_int(self.COUNT_PATH)
        max_ = self._read_int(self.MAX_PATH)
        return MetricSnapshot(
            server_id=self.server_id,
            timestamp=0.0,
            conntrack_count=count,
            tcp_new=0,
        )

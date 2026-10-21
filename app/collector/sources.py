from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from app.storage.models import ConnectionMetric, TrafficMetric

__all__ = [
    "MetricSource",
    "MetricSnapshot",
    "MetricCollector",
]


@dataclass
class MetricSnapshot:

    server_id: int
    timestamp: float
    in_bytes: int = 0
    out_bytes: int = 0
    in_pps: float = 0.0
    out_pps: float = 0.0
    in_bps: float = 0.0
    out_bps: float = 0.0
    tcp_new: int = 0
    udp_pps: float = 0.0
    conntrack_count: int = 0
    new_sources: int = 0
    error: Optional[str] = None


class MetricSource(ABC):

    @abstractmethod
    def read(self) -> MetricSnapshot:
        pass

    @abstractmethod
    def name(self) -> str:
        pass


class MetricCollector:

    def __init__(self, interval_sec: float = 1.0) -> None:
        self.interval_sec = interval_sec
        self.sources: list[MetricSource] = []
        self._prev: dict[str, MetricSnapshot] = {}
        self._running = False

    def add_source(self, source: MetricSource) -> None:
        self.sources.append(source)

    def _compute_delta(
        self, source_name: str, current: MetricSnapshot
    ) -> MetricSnapshot:
        prev = self._prev.get(source_name)
        if prev is None:
            self._prev[source_name] = current
            return current

        dt = current.timestamp - prev.timestamp
        if dt <= 0:
            return current

        def delta(cur_val: float, prev_val: float) -> float:
            if cur_val < prev_val:
                return cur_val
            return cur_val - prev_val

        return MetricSnapshot(
            server_id=current.server_id,
            timestamp=current.timestamp,
            in_bytes=int(delta(current.in_bytes, prev.in_bytes)),
            out_bytes=int(delta(current.out_bytes, prev.out_bytes)),
            in_pps=delta(current.in_pps, prev.in_pps) / dt,
            out_pps=delta(current.out_pps, prev.out_pps) / dt,
            in_bps=delta(current.in_bps, prev.in_bps) / dt,
            out_bps=delta(current.out_bps, prev.out_bps) / dt,
            tcp_new=int(delta(current.tcp_new, prev.tcp_new)),
            udp_pps=delta(current.udp_pps, prev.udp_pps) / dt,
            conntrack_count=current.conntrack_count,
            new_sources=int(delta(current.new_sources, prev.new_sources)),
            error=current.error,
        )

    def collect_once(self) -> list[MetricSnapshot]:
        results: list[MetricSnapshot] = []
        now = time.time()

        for source in self.sources:
            try:
                raw = source.read()
                raw.timestamp = now
                snap = self._compute_delta(source.name(), raw)
                self._prev[source.name()] = raw
                results.append(snap)
            except Exception as exc:
                results.append(
                    MetricSnapshot(
                        server_id=0,
                        timestamp=now,
                        error=str(exc),
                    )
                )

        return results

    def to_storage_models(
        self, snapshots: list[MetricSnapshot]
    ) -> tuple[list[TrafficMetric], list[ConnectionMetric]]:
        traffic: list[TrafficMetric] = []
        connections: list[ConnectionMetric] = []
        from datetime import datetime

        for s in snapshots:
            if s.error:
                continue
            ts = datetime.utcfromtimestamp(s.timestamp)
            traffic.append(
                TrafficMetric(
                    server_id=s.server_id,
                    timestamp=ts,
                    in_bytes=s.in_bytes,
                    out_bytes=s.out_bytes,
                    in_pps=s.in_pps,
                    out_pps=s.out_pps,
                    in_bps=s.in_bps,
                    out_bps=s.out_bps,
                )
            )
            connections.append(
                ConnectionMetric(
                    server_id=s.server_id,
                    timestamp=ts,
                    tcp_new=s.tcp_new,
                    udp_pps=s.udp_pps,
                    conntrack_count=s.conntrack_count,
                    new_sources=s.new_sources,
                )
            )
        return traffic, connections

    def run_forever(self, callback) -> None:
        self._running = True
        while self._running:
            start = time.time()
            snaps = self.collect_once()
            callback(snaps)
            elapsed = time.time() - start
            sleep_for = max(0.0, self.interval_sec - elapsed)
            time.sleep(sleep_for)

    def stop(self) -> None:
        self._running = False

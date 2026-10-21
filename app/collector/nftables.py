"""Collector: статистика и правила nftables."""

from __future__ import annotations

import json
import subprocess
from typing import Optional

from app.collector.sources import MetricSnapshot, MetricSource

__all__ = ["NftablesSource"]


class NftablesSource(MetricSource):
    """
    Читает счётчики правил nftables через `nft -j list ruleset`.
    Возвращает метрики по защищаемым серверам, портам и направлениям.
    """

    def __init__(self, server_id: int) -> None:
        self.server_id = server_id

    def name(self) -> str:
        return "nftables"

    def _run_nft(self) -> dict:
        result = subprocess.run(
            ["nft", "-j", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return {}
        try:
            return json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return {}

    def _extract_counters(self, ruleset: dict) -> tuple[int, int]:
        """Суммирует пакеты и байты из счётчиков правил."""
        in_packets = 0
        in_bytes = 0
        nftables = ruleset.get("nftables", [])
        for item in nftables:
            rule = item.get("rule", {})
            exprs = rule.get("expr", [])
            for expr in exprs:
                if "counter" in expr:
                    counter = expr["counter"]
                    in_packets += int(counter.get("packets", 0))
                    in_bytes += int(counter.get("bytes", 0))
        return in_packets, in_bytes

    def read(self) -> MetricSnapshot:
        try:
            ruleset = self._run_nft()
            packets, bytes_ = self._extract_counters(ruleset)
            return MetricSnapshot(
                server_id=self.server_id,
                timestamp=0.0,
                in_bytes=bytes_,
                in_pps=float(packets),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            return MetricSnapshot(
                server_id=self.server_id,
                timestamp=0.0,
                error=f"nftables read failed: {exc}",
            )

from __future__ import annotations

import os
from typing import Optional

from app.collector.sources import MetricSnapshot, MetricSource

__all__ = ["InterfaceSource"]


class InterfaceSource(MetricSource):

    SYS_CLASS_NET = "/sys/class/net"

    def __init__(
        self,
        server_id: int,
        interface: str,
        in_iface: Optional[str] = None,
        out_iface: Optional[str] = None,
    ) -> None:
        self.server_id = server_id
        self.interface = interface
        self.in_iface = in_iface or interface
        self.out_iface = out_iface or interface

    def name(self) -> str:
        return f"interface:{self.interface}"

    def _read_counter(self, path: str) -> int:
        try:
            with open(path, "r", encoding="ascii") as fh:
                return int(fh.read().strip())
        except (FileNotFoundError, ValueError, PermissionError):
            return 0

    def read(self) -> MetricSnapshot:
        in_path = os.path.join(
            self.SYS_CLASS_NET, self.in_iface, "statistics", "rx_bytes"
        )
        out_path = os.path.join(
            self.SYS_CLASS_NET, self.out_iface, "statistics", "tx_bytes"
        )
        in_packets_path = os.path.join(
            self.SYS_CLASS_NET, self.in_iface, "statistics", "rx_packets"
        )
        out_packets_path = os.path.join(
            self.SYS_CLASS_NET, self.out_iface, "statistics", "tx_packets"
        )
        in_drops_path = os.path.join(
            self.SYS_CLASS_NET, self.in_iface, "statistics", "rx_dropped"
        )
        out_errors_path = os.path.join(
            self.SYS_CLASS_NET, self.out_iface, "statistics", "tx_errors"
        )

        return MetricSnapshot(
            server_id=self.server_id,
            timestamp=0.0,
            in_bytes=self._read_counter(in_path),
            out_bytes=self._read_counter(out_path),
            in_pps=float(self._read_counter(in_packets_path)),
            out_pps=float(self._read_counter(out_packets_path)),
        )

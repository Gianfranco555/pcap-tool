"""Simple metrics collector for parsed PCAP records."""

from collections import Counter
from typing import Dict

from ..parser import PcapRecord


class StatsCollector:
    """Accumulate protocol and port statistics from :class:`PcapRecord`."""

    def __init__(self) -> None:
        self.protocol_counts: Counter[str] = Counter()
        self.port_counts: Counter[str] = Counter()

    def add(self, record: PcapRecord) -> None:
        """Update metrics for a single record."""
        proto = record.protocol
        if proto:
            key = str(proto).lower()
            self.protocol_counts[key] += 1

            if key in {"tcp", "udp"}:
                port_val = int(record.destination_port or 0)
                port_key = f"{key}_{port_val}"
                self.port_counts[port_key] += 1

    def summary(self) -> Dict[str, Dict[str, int]]:
        """Return collected metrics."""
        return {
            "protocols": dict(self.protocol_counts),
            "top_ports": dict(self.port_counts.most_common(10)),
        }

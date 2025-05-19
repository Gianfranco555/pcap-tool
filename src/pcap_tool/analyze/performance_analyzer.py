"""Basic network performance metrics from :class:`PcapRecord` streams."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List
import numpy as np

from ..models import PcapRecord
from ..utils import safe_int_or_default


class PerformanceAnalyzer:
    """Track TCP handshake RTT and retransmission counts."""

    def __init__(self) -> None:
        # Keyed by a stable flow identifier string
        self.tcp_syn_timestamps: defaultdict[str, Dict[str, float | int | None]] = defaultdict(
            lambda: {"client_syn_ts": None, "client_seq": None}
        )
        self.rtt_samples_ms: List[float] = []
        self.tcp_total_packets: int = 0
        self.tcp_retransmissions: int = 0
        # Placeholder for potential QUIC tracking
        # self.quic_initial_packets: Dict[str, float] = {}

    def add_packet(self, record: PcapRecord, flow_id_str: str, is_client_packet: bool) -> None:
        """Add a packet to the analyzer.

        Parameters
        ----------
        record:
            Parsed packet record.
        flow_id_str:
            Unique identifier for the flow from the client perspective.
        is_client_packet:
            ``True`` if the packet direction is client -> server.
        """
        if record.protocol and record.protocol.upper() == "TCP":
            self.tcp_total_packets += 1
            if record.tcp_analysis_retransmission_flags:
                self.tcp_retransmissions += 1

            if is_client_packet and record.tcp_flags_syn and not record.tcp_flags_ack:
                entry = self.tcp_syn_timestamps[flow_id_str]
                entry["client_syn_ts"] = record.timestamp
                entry["client_seq"] = safe_int_or_default(record.tcp_sequence_number, 0)

            if (
                not is_client_packet
                and record.tcp_flags_syn
                and record.tcp_flags_ack
            ):
                entry = self.tcp_syn_timestamps.get(flow_id_str)
                if (
                    entry
                    and entry.get("client_syn_ts") is not None
                    and (
                        safe_int_or_default(record.tcp_acknowledgment_number, -1)
                        == (entry.get("client_seq") or 0) + 1
                    )
                ):
                    rtt = (record.timestamp - float(entry["client_syn_ts"])) * 1000
                    self.rtt_samples_ms.append(rtt)
                    self.tcp_syn_timestamps[flow_id_str] = {
                        "client_syn_ts": None,
                        "client_seq": None,
                    }

    def get_summary(self) -> Dict[str, object]:
        """Return aggregated performance metrics."""
        if self.rtt_samples_ms:
            arr = np.array(self.rtt_samples_ms)
            rtt_summary = {
                "median": float(np.median(arr)),
                "p95": float(np.percentile(arr, 95)),
                "min": float(arr.min()),
                "max": float(arr.max()),
                "samples": len(self.rtt_samples_ms),
            }
        else:
            rtt_summary = {"median": None, "p95": None, "min": None, "max": None, "samples": 0}

        if self.tcp_total_packets:
            retrans_percent = (self.tcp_retransmissions / self.tcp_total_packets) * 100
        else:
            retrans_percent = 0.0

        return {
            "tcp_rtt_ms": rtt_summary,
            "tcp_retransmission_ratio_percent": retrans_percent,
        }

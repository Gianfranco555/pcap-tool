"""Basic network performance metrics from :class:`PcapRecord` streams."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List
import numpy as np
import pandas as pd

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
        self.tls_handshake_start: defaultdict[str, float | None] = defaultdict(lambda: None)
        self.tls_alert_deltas_ms: List[float] = []
        # Placeholder for potential QUIC tracking
        # self.quic_initial_packets: Dict[str, float] = {}

    @staticmethod
    def collect_rtt_samples(packets_df: pd.DataFrame) -> List[float]:
        """Return RTT samples in ms from SYN/SYN-ACK pairs in ``packets_df``."""

        if packets_df.empty:
            return []

        df = packets_df.sort_values("timestamp")
        syn_times: Dict[tuple[str, int, str, int, str], float] = {}
        rtts: List[float] = []

        for row in df.itertuples(index=False):
            proto = getattr(row, "protocol", None)
            if not proto or str(proto).upper() != "TCP":
                continue

            is_client = getattr(row, "is_source_client", None)
            if is_client is None:
                is_client = getattr(row, "is_src_client", None)

            syn = getattr(row, "tcp_flags_syn", False)
            ack = getattr(row, "tcp_flags_ack", False)

            src_ip = getattr(row, "source_ip", None)
            dst_ip = getattr(row, "destination_ip", None)
            src_port = safe_int_or_default(getattr(row, "source_port", None), 0)
            dst_port = safe_int_or_default(getattr(row, "destination_port", None), 0)

            if is_client and syn and not ack:
                key = (src_ip or "", src_port, dst_ip or "", dst_port, "TCP")
                if key not in syn_times:
                    syn_times[key] = getattr(row, "timestamp", 0.0)
                continue

            if not is_client and syn and ack:
                rev_key = (dst_ip or "", dst_port, src_ip or "", src_port, "TCP")
                syn_ts = syn_times.get(rev_key)
                if syn_ts is not None:
                    diff = getattr(row, "timestamp", 0.0) - syn_ts
                    if 0 <= diff <= 3.0:
                        rtts.append(diff * 1000.0)
                    del syn_times[rev_key]

        return rtts

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

        if record.tls_handshake_type and self.tls_handshake_start[flow_id_str] is None:
            self.tls_handshake_start[flow_id_str] = record.timestamp

        if record.tls_alert_message_description:
            start_ts = self.tls_handshake_start.get(flow_id_str)
            if start_ts is not None:
                delta = (record.timestamp - start_ts) * 1000.0
                if delta >= 0:
                    self.tls_alert_deltas_ms.append(delta)
                self.tls_handshake_start[flow_id_str] = None

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
            rtt_limited = False
        else:
            rtt_summary = {"median": None, "p95": None, "min": None, "max": None, "samples": 0}
            rtt_limited = True

        if self.tcp_total_packets:
            retrans_percent = (self.tcp_retransmissions / self.tcp_total_packets) * 100
        else:
            retrans_percent = 0.0

        if self.rtt_samples_ms:
            tcp_syn_rtt_ms = float(np.median(np.array(self.rtt_samples_ms)))
        else:
            tcp_syn_rtt_ms = float("nan")

        if self.tls_alert_deltas_ms:
            tls_time_to_alert_ms = float(np.median(np.array(self.tls_alert_deltas_ms)))
        else:
            tls_time_to_alert_ms = float("nan")

        return {
            "tcp_rtt_ms": rtt_summary,
            "tcp_syn_rtt_ms": tcp_syn_rtt_ms,
            "tls_time_to_alert_ms": tls_time_to_alert_ms,
            "tcp_retransmission_ratio_percent": retrans_percent,
            "rtt_limited_data": rtt_limited,
        }

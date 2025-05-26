"""Basic network performance metrics from :class:`PcapRecord` streams."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List
import numpy as np
import pandas as pd

from ...core.models import PcapRecord
from ...utils import safe_int_or_default
from ...core.config import settings
from ...core.decorators import handle_analysis_errors, log_performance


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
    @handle_analysis_errors
    @log_performance
    def collect_rtt_samples(packets_df: pd.DataFrame) -> List[float]:
        """Return RTT samples in ms from SYN/SYN-ACK pairs in ``packets_df``."""

        if packets_df.empty:
            return []

        df = packets_df.sort_values("timestamp")
        df = df[df["protocol"].str.upper() == "TCP"]

        syn = df[df["tcp_flags_syn"] & ~df["tcp_flags_ack"]]
        synack = df[df["tcp_flags_syn"] & df["tcp_flags_ack"]]

        syn = syn.assign(
            flow_key=list(
                zip(
                    syn["source_ip"].fillna(""),
                    syn["source_port"].apply(lambda x: safe_int_or_default(x, 0)),
                    syn["destination_ip"].fillna(""),
                    syn["destination_port"].apply(lambda x: safe_int_or_default(x, 0)),
                )
            )
        )

        synack = synack.assign(
            flow_key=list(
                zip(
                    synack["destination_ip"].fillna(""),
                    synack["destination_port"].apply(lambda x: safe_int_or_default(x, 0)),
                    synack["source_ip"].fillna(""),
                    synack["source_port"].apply(lambda x: safe_int_or_default(x, 0)),
                )
            )
        )

        syn_first = syn.groupby("flow_key", as_index=False)["timestamp"].min()
        synack_first = synack.groupby("flow_key", as_index=False)["timestamp"].min()

        merged = syn_first.merge(
            synack_first, on="flow_key", suffixes=("_syn", "_ack")
        )
        merged = merged[merged["timestamp_ack"] >= merged["timestamp_syn"]]
        merged["rtt"] = (merged["timestamp_ack"] - merged["timestamp_syn"]) * 1000.0
        merged = merged[merged["rtt"] <= settings.tcp_rtt_timeout * 1000.0]

        return merged["rtt"].tolist()

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

    @handle_analysis_errors
    @log_performance
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

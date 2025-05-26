# src/pcap_tool/metrics/flow_table.py
"""Simple in-memory flow table with per-second byte counters."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Tuple, Iterable

import pandas as pd

from ..core.models import PcapRecord
from ..utils import safe_int_or_default
from ..heuristics.protocol_inference import guess_l7_protocol


@dataclass
class Flow:
    """Bi-directional flow statistics."""

    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    pkts_c2s: int = 0
    pkts_s2c: int = 0
    start_ts: float = 0.0
    end_ts: float = 0.0
    bins_c2s: defaultdict[int, int] = field(default_factory=lambda: defaultdict(int))
    bins_s2c: defaultdict[int, int] = field(default_factory=lambda: defaultdict(int))


class FlowTable:
    """Track flows and produce summary DataFrames."""

    def __init__(self) -> None:
        self.flows: Dict[Tuple[str, str, int, int, str], Flow] = {}

    def _get_key(self, rec: PcapRecord, is_src_client: bool) -> Tuple[str, str, int, int, str]:
        src_ip = rec.source_ip or ""
        dest_ip = rec.destination_ip or ""
        src_port = safe_int_or_default(rec.source_port, 0)
        dest_port = safe_int_or_default(rec.destination_port, 0)
        proto = rec.protocol or ""
        if is_src_client:
            return src_ip, dest_ip, src_port, dest_port, proto
        return dest_ip, src_ip, dest_port, src_port, proto

    def add_packet(self, record: PcapRecord, is_src_client: bool) -> None:
        """Update flow counters from ``record``."""
        key = self._get_key(record, is_src_client)
        flow = self.flows.get(key)
        ts = float(record.timestamp or 0.0)
        length = safe_int_or_default(record.packet_length, 0)
        if flow is None:
            flow = Flow(
                src_ip=key[0],
                dest_ip=key[1],
                src_port=key[2],
                dest_port=key[3],
                protocol=key[4],
                start_ts=ts,
                end_ts=ts,
            )
            self.flows[key] = flow
        else:
            flow.end_ts = max(flow.end_ts, ts)
            if flow.start_ts == 0.0 or ts < flow.start_ts:
                flow.start_ts = ts
        bin_sec = safe_int_or_default(ts, 0)
        if is_src_client:
            flow.bytes_c2s += length
            flow.pkts_c2s += 1
            flow.bins_c2s[bin_sec] += length
        else:
            flow.bytes_s2c += length
            flow.pkts_s2c += 1
            flow.bins_s2c[bin_sec] += length

    @staticmethod
    def _sparkline(bins: defaultdict[int, int], start_ts: float, end_ts: float) -> str:
        if not bins:
            return ""
        start = safe_int_or_default(start_ts, 0)
        end = safe_int_or_default(end_ts, 0)
        return ",".join(str(bins.get(sec, 0)) for sec in range(start, end + 1))

    def get_summary_df(
        self, top_n_bytes: int = 20, top_n_packets: int = 20
    ) -> tuple["pd.DataFrame", "pd.DataFrame"]:
        """Return two DataFrames ordered by bytes and packet count."""
        import pandas as pd

        rows = []
        for flow in self.flows.values():
            bytes_total = flow.bytes_c2s + flow.bytes_s2c
            pkts_total = flow.pkts_c2s + flow.pkts_s2c
            rows.append(
                {
                    "src_ip": flow.src_ip,
                    "dest_ip": flow.dest_ip,
                    "src_port": flow.src_port,
                    "dest_port": flow.dest_port,
                    "protocol": flow.protocol,
                    "l7_protocol_guess": guess_l7_protocol(
                        {
                            "protocol": flow.protocol,
                            "src_port": flow.src_port,
                            "dest_port": flow.dest_port,
                        }
                    ),
                    "bytes_c2s": flow.bytes_c2s,
                    "bytes_s2c": flow.bytes_s2c,
                    "bytes_total": bytes_total,
                    "pkts_c2s": flow.pkts_c2s,
                    "pkts_s2c": flow.pkts_s2c,
                    "pkts_total": pkts_total,
                    "sparkline_bytes_c2s": self._sparkline(flow.bins_c2s, flow.start_ts, flow.end_ts),
                    "sparkline_bytes_s2c": self._sparkline(flow.bins_s2c, flow.start_ts, flow.end_ts),
                }
            )
        if not rows:
            empty = pd.DataFrame()
            return empty, empty
        df = pd.DataFrame(rows)
        df["l7_protocol_guess"] = df.apply(guess_l7_protocol, axis=1)
        df_bytes = (
            df.sort_values("bytes_total", ascending=False)
            .head(top_n_bytes)
            .reset_index(drop=True)
        )
        df_pkts = (
            df.sort_values("pkts_total", ascending=False)
            .head(top_n_packets)
            .reset_index(drop=True)
        )
        return df_bytes, df_pkts

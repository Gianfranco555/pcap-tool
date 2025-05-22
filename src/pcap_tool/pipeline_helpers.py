"""Helper functions for the analysis pipeline."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, List

import pandas as pd

from .parser import iter_parsed_frames
from .models import PcapRecord
from .metrics.stats_collector import StatsCollector
from .metrics.flow_table import FlowTable
from .metrics.timeline_builder import TimelineBuilder
from .analyze import PerformanceAnalyzer
from .utils import safe_int

INT_COLS: List[str] = [
    "source_port",
    "destination_port",
    "packet_length",
    "frame_number",
    "tcp_sequence_number",
    "tcp_acknowledgment_number",
    "tcp_window_size",
    "tcp_options_mss",
    "tcp_options_window_scale",
    "icmp_type",
    "icmp_code",
    "ip_ttl",
    "dscp_value",
    "arp_opcode",
    "tcp_stream_index",
    "dup_ack_num",
    "adv_window",
    "icmp_fragmentation_needed_original_mtu",
]

FILL_VALUES: Dict[str, int] = {
    "source_port": -1,
    "destination_port": -1,
    "packet_length": 0,
    "frame_number": -1,
    "tcp_sequence_number": -1,
    "tcp_acknowledgment_number": -1,
    "tcp_window_size": 0,
    "tcp_options_mss": 0,
    "tcp_options_window_scale": 0,
    "icmp_type": -1,
    "icmp_code": -1,
    "ip_ttl": 0,
    "dscp_value": 0,
    "arp_opcode": -1,
    "tcp_stream_index": -1,
    "dup_ack_num": -1,
    "adv_window": 0,
    "icmp_fragmentation_needed_original_mtu": 0,
}


def _determine_client(
    rec: PcapRecord, cache: Dict[str, tuple[str | None, int | None]], key: str
) -> bool:
    client = cache.get(key)
    if client is None:
        if (
            rec.protocol
            and rec.protocol.upper() == "TCP"
            and rec.tcp_flags_syn
            and not rec.tcp_flags_ack
        ) or (rec.protocol and rec.protocol.upper() == "UDP"):
            cache[key] = (rec.source_ip, rec.source_port)
        return True
    return rec.source_ip == client[0] and rec.source_port == client[1]


def _clean_int_columns(df: pd.DataFrame) -> None:
    for col in INT_COLS:
        if col in df.columns:
            df[col] = safe_int(df[col], FILL_VALUES.get(col, 0))


def load_packets(
    pcap_path: Path,
    on_progress: Callable[[int, int | None], None] | None = None,
) -> List[PcapRecord]:
    """Parse ``pcap_path`` into :class:`PcapRecord` objects.

    Parameters
    ----------
    pcap_path:
        Location of the PCAP or PCAP-ng file to parse.
    on_progress:
        Optional callback receiving the count of packets processed and an
        estimated total. When provided, this is forwarded to
        :func:`iter_parsed_frames` so callers can report progress.
    """

    records: List[PcapRecord] = []
    field_set = set(PcapRecord.__dataclass_fields__.keys())
    for chunk in iter_parsed_frames(pcap_path, on_progress=on_progress):
        for row in chunk.itertuples(index=False):
            data = {k: getattr(row, k) for k in field_set if hasattr(row, k)}
            records.append(PcapRecord(**data))
    return records


def collect_stats(records: List[PcapRecord]) -> dict[str, Any]:
    """Return packet dataframe and metric collectors for ``records``."""
    from .pipeline_app import _derive_flow_id, _flow_cache_key

    sc = StatsCollector()
    ft = FlowTable()
    tl = TimelineBuilder()
    pa = PerformanceAnalyzer()
    cache: Dict[str, tuple[str | None, int | None]] = {}

    for rec in records:
        sc.add(rec)
        tl.add_packet(rec)
        key = _flow_cache_key(rec)
        rec.is_source_client = _determine_client(rec, cache, key)
        fid = _derive_flow_id(rec)
        ft.add_packet(rec, rec.is_source_client)
        pa.add_packet(rec, "-".join(map(str, fid)), rec.is_source_client)

    packet_df = pd.DataFrame([asdict(r) for r in records])
    _clean_int_columns(packet_df)

    return {
        "packet_df": packet_df,
        "stats_collector": sc,
        "flow_table": ft,
        "performance_analyzer": pa,
        "timeline_builder": tl,
    }


def build_metrics(df: pd.DataFrame, heuristics_rules: Path) -> pd.DataFrame:
    """Tag ``df`` flows using the provided heuristic rules."""
    from pcap_tool.heuristics.engine import HeuristicEngine

    engine = HeuristicEngine(str(heuristics_rules))
    return engine.tag_flows(df)


def generate_reports(metrics: dict, flows_df: pd.DataFrame, summary_text: str | None = None) -> bytes:
    """Return PDF bytes for the provided metrics."""
    from .pdf_report import generate_pdf_report

    return generate_pdf_report(metrics, flows_df, summary_text)

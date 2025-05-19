
"""Command line entry for the hybrid PCAP analysis pipeline."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
from typing import List, Tuple

import pandas as pd

from .parser import iter_parsed_frames, PcapRecord
from .metrics.stats_collector import StatsCollector
from .metrics.flow_table import FlowTable
from .metrics.timeline_builder import TimelineBuilder
from .enrichment import Enricher
from .enrich import service_guesser
from .analyze import PerformanceAnalyzer, ErrorSummarizer, SecurityAuditor
from .metrics_builder import MetricsBuilder
from heuristics.engine import HeuristicEngine
from llm_summarizer import LLMSummarizer
from .pdf_report import generate_pdf_report


def _derive_flow_id(rec: PcapRecord) -> Tuple[str, str, int, int, str]:
    """Return a tuple uniquely identifying the flow."""
    return (
        rec.source_ip or "",
        rec.destination_ip or "",
        int(rec.source_port or 0),
        int(rec.destination_port or 0),
        rec.protocol or "",
    )


def _flow_cache_key(record: PcapRecord) -> str:
    """Return a direction-agnostic identifier for caching client IP/port."""
    if record.tcp_stream_index is not None:
        return f"TCP_STREAM_{record.tcp_stream_index}"
    if record.source_ip and record.destination_ip and record.protocol:
        props = sorted(
            [
                (record.source_ip, int(record.source_port or 0)),
                (record.destination_ip, int(record.destination_port or 0)),
            ]
        )
        return f"{record.protocol}_{props[0][0]}:{props[0][1]}_{props[1][0]}:{props[1][1]}"
    return f"UNKNOWN_FLOW_{record.frame_number}"


def run_analysis(pcap_path: Path, rules_path: Path) -> Tuple[dict, pd.DataFrame, str, bytes]:
    """Run the full analysis pipeline and return outputs."""

    enricher = Enricher()
    stats_collector = StatsCollector()
    flow_table = FlowTable()
    service = service_guesser
    performance_analyzer = PerformanceAnalyzer()
    timeline_builder = TimelineBuilder()
    error_summarizer = ErrorSummarizer()
    security_auditor = SecurityAuditor(enricher)
    heuristic_engine = HeuristicEngine(str(rules_path))
    metrics_builder = MetricsBuilder(
        stats_collector,
        flow_table,
        enricher,
        service,
        performance_analyzer,
        timeline_builder,
        error_summarizer,
        security_auditor,
        heuristic_engine,
    )
    llm_summarizer = LLMSummarizer()

    packet_records: List[PcapRecord] = []
    flow_clients_cache: dict[str, tuple[str | None, int | None]] = {}

    for chunk in iter_parsed_frames(pcap_path):
        for row in chunk.itertuples(index=False):
            rec = PcapRecord(**row._asdict())
            stats_collector.add(rec)
            timeline_builder.add_packet(rec)

            cache_key = _flow_cache_key(rec)
            client = flow_clients_cache.get(cache_key)

            if client is None:
                if rec.protocol and rec.protocol.upper() == "TCP" and rec.tcp_flags_syn and not rec.tcp_flags_ack:
                    flow_clients_cache[cache_key] = (rec.source_ip, rec.source_port)
                    is_client = True
                elif rec.protocol and rec.protocol.upper() == "UDP":
                    flow_clients_cache[cache_key] = (rec.source_ip, rec.source_port)
                    is_client = True
                else:
                    is_client = True
            else:
                is_client = rec.source_ip == client[0] and rec.source_port == client[1]

            rec.is_source_client = is_client
            flow_id = _derive_flow_id(rec)
            flow_table.add_packet(rec, is_client)
            performance_analyzer.add_packet(rec, "-".join(map(str, flow_id)), is_client)
            packet_records.append(rec)

    packet_df = pd.DataFrame([asdict(r) for r in packet_records])

    int_cols_to_clean = [
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

    fill_values_for_int_cols = {
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

    for col in int_cols_to_clean:
        if col in packet_df.columns:
            if packet_df[col].isnull().any():
                packet_df[col] = packet_df[col].fillna(
                    fill_values_for_int_cols.get(col, 0)
                )
            packet_df[col] = packet_df[col].astype("int64")

    flow_summary_df, _ = flow_table.get_summary_df()
    tagged_flow_df = heuristic_engine.tag_flows(flow_summary_df)
    metrics_json = metrics_builder.build_metrics(packet_df, tagged_flow_df)

    text_summary = llm_summarizer.generate_text_summary(metrics_json)
    pdf_bytes = generate_pdf_report(metrics_json, tagged_flow_df)

    return metrics_json, tagged_flow_df, text_summary, pdf_bytes


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Hybrid PCAP analysis pipeline")
    parser.add_argument("pcap", type=Path, help="PCAP or PCAP-ng file")
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parent / "heuristics" / "rules.yaml", help="Path to heuristic rules")
    parser.add_argument("--summary", action="store_true", help="Print text summary to stdout")
    args = parser.parse_args(argv)

    metrics, tagged_flows, text_summary, _ = run_analysis(args.pcap, args.rules)

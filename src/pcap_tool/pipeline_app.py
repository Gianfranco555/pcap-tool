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

    for chunk in iter_parsed_frames(pcap_path):
        for row in chunk.itertuples(index=False):
            rec = PcapRecord(**row._asdict())
            stats_collector.add(rec)
            timeline_builder.add_packet(rec)
            is_client = bool(rec.is_src_client) if rec.is_src_client is not None else True
            flow_id = _derive_flow_id(rec)
            flow_table.add_packet(rec, is_client)
            performance_analyzer.add_packet(rec, "-".join(map(str, flow_id)), is_client)
            packet_records.append(rec)

    packet_df = pd.DataFrame([asdict(r) for r in packet_records])

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

    if args.summary:
        print(text_summary)
    else:
        print(metrics)
        print(f"Tagged flows: {len(tagged_flows)}")


if __name__ == "__main__":
    main()


"""Command line entry for the hybrid PCAP analysis pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable, List, Tuple

import pandas as pd
from .models import PcapRecord
from .enrichment import Enricher
from .enrich import service_guesser
from .analyze import ErrorSummarizer, SecurityAuditor
from .metrics_builder import MetricsBuilder
from pcap_tool.heuristics.engine import HeuristicEngine, VectorisedHeuristicEngine
from .llm_summarizer import LLMSummarizer
from .utils import safe_int_or_default
from .pipeline_helpers import (
    load_packets,
    collect_stats,
    build_metrics,
    generate_reports,
)
from .core.decorators import handle_analysis_errors, log_performance


def _derive_flow_id(rec: PcapRecord) -> Tuple[str, str, int, int, str]:
    """Return a tuple uniquely identifying the flow."""
    return (
        rec.source_ip or "",
        rec.destination_ip or "",
        safe_int_or_default(rec.source_port, 0),
        safe_int_or_default(rec.destination_port, 0),
        rec.protocol or "",
    )


def _flow_cache_key(record: PcapRecord) -> str:
    """Return a direction-agnostic identifier for caching client IP/port."""
    if record.tcp_stream_index is not None:
        return f"TCP_STREAM_{record.tcp_stream_index}"
    if record.source_ip and record.destination_ip and record.protocol:
        props = sorted(
            [
                (
                    record.source_ip,
                    safe_int_or_default(record.source_port, 0),
                ),
                (
                    record.destination_ip,
                    safe_int_or_default(record.destination_port, 0),
                ),
            ]
        )
        return f"{record.protocol}_{props[0][0]}:{props[0][1]}_{props[1][0]}:{props[1][1]}"
    return f"UNKNOWN_FLOW_{record.frame_number}"


@handle_analysis_errors
@log_performance
def run_analysis(
    pcap_path: Path,
    rules_path: Path,
    on_progress: Callable[[int, int | None], None] | None = None,
) -> Tuple[dict, pd.DataFrame, str, bytes]:
    """Run the full analysis pipeline and return outputs."""

    records = load_packets(pcap_path, on_progress=on_progress)
    stats = collect_stats(records)

    enricher = Enricher()
    service = service_guesser
    error_summarizer = ErrorSummarizer()
    security_auditor = SecurityAuditor(enricher)
    heuristic_engine = HeuristicEngine(str(rules_path))
    metrics_builder = MetricsBuilder(
        stats["stats_collector"],
        stats["flow_table"],
        enricher,
        service,
        stats["performance_analyzer"],
        stats["timeline_builder"],
        error_summarizer,
        security_auditor,
        heuristic_engine,
    )

    flow_summary_df, _ = stats["flow_table"].get_summary_df()
    if isinstance(heuristic_engine, VectorisedHeuristicEngine):
        tagged_flow_df = heuristic_engine.tag_flows(stats["packet_df"])
    else:
        tagged_flow_df = build_metrics(flow_summary_df, rules_path)
    metrics_json = metrics_builder.build_metrics(stats["packet_df"], tagged_flow_df)

    llm_summarizer = LLMSummarizer()
    text_summary = llm_summarizer.generate_text_summary(metrics_json)
    pdf_bytes = generate_reports(metrics_json, tagged_flow_df, text_summary)

    return metrics_json, tagged_flow_df, text_summary, pdf_bytes


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Hybrid PCAP analysis pipeline")
    parser.add_argument("pcap", type=Path, help="PCAP or PCAP-ng file")
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parent / "heuristics" / "rules.yaml", help="Path to heuristic rules")
    parser.add_argument("--summary", action="store_true", help="Print text summary to stdout")
    args = parser.parse_args(argv)

    metrics, tagged_flows, text_summary, _ = run_analysis(args.pcap, args.rules)

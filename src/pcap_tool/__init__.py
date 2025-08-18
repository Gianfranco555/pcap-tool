# src/pcap_tool/__init__.py
from .parser import (
    parse_pcap,
    parse_pcap_to_df,
    iter_parsed_frames,
    validate_pcap_file,
)
from .core.models import PcapRecord, ParsedHandle
from .reporting.pdf_report import generate_pdf_report
from .reporting.summary import generate_summary_df, export_summary_excel
from .utils import export_to_csv, anonymize_ip
from .ai import prepare_ai_data
from .metrics.stats_collector import StatsCollector
from .analysis import PerformanceAnalyzer, ErrorSummarizer
from .heuristics.engine import VectorisedHeuristicEngine
from .pipeline import Pipeline, BaseProcessor, BaseAnalyzer, BaseReporter
from . import orchestrator


__all__ = [
    "orchestrator",
    "parse_pcap",
    "parse_pcap_to_df",
    "iter_parsed_frames",
    "PcapRecord",
    "ParsedHandle",
    "validate_pcap_file",
    "generate_pdf_report",
    "generate_summary_df",
    "export_summary_excel",
    "export_to_csv",
    "anonymize_ip",
    "prepare_ai_data",
    "StatsCollector",
    "PerformanceAnalyzer",
    "ErrorSummarizer",
    "VectorisedHeuristicEngine",
    "Pipeline",
    "BaseProcessor",
    "BaseAnalyzer",
    "BaseReporter",
]

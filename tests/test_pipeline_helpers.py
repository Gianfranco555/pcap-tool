import pandas as pd
import pytest
from pathlib import Path

from pcap_tool.pipeline_helpers import (
    load_packets,
    collect_stats,
    build_metrics,
    generate_reports,
)
from pcap_tool.models import PcapRecord


def test_load_packets(example_pcap: Path):
    records = load_packets(example_pcap)
    assert records
    assert isinstance(records[0], PcapRecord)


def test_collect_stats_basic():
    records = [
        PcapRecord(frame_number=1, timestamp=1.0, protocol="TCP"),
        PcapRecord(frame_number=2, timestamp=2.0, protocol="TCP"),
    ]
    result = collect_stats(records)
    assert set(result.keys()) == {
        "packet_df",
        "stats_collector",
        "flow_table",
        "performance_analyzer",
        "timeline_builder",
    }
    assert len(result["packet_df"]) == 2


def test_build_metrics(tmp_path: Path):
    records = [PcapRecord(frame_number=1, timestamp=1.0, protocol="TCP")]
    stats = collect_stats(records)
    df, _ = stats["flow_table"].get_summary_df()
    rules = Path("src/heuristics/rules.yaml")
    tagged = build_metrics(df, rules)
    assert isinstance(tagged, pd.DataFrame)
    assert len(tagged) == len(df)


def test_generate_reports(monkeypatch):
    monkeypatch.setattr(
        "pcap_tool.pdf_report.generate_pdf_report", lambda metrics, df: b"pdf"
    )
    pdf = generate_reports({}, pd.DataFrame())
    assert pdf == b"pdf"

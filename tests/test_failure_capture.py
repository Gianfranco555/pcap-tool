import pandas as pd
import pytest
from pathlib import Path

from pcap_tool.pipeline_helpers import collect_stats
from pcap_tool.models import PcapRecord
from pcap_tool.heuristics.engine import (
    HeuristicEngine,
    VectorisedHeuristicEngine,
)
from pcap_tool.metrics_builder import MetricsBuilder
from pcap_tool.enrichment import Enricher
from pcap_tool.enrich.service_guesser import guess_service
from pcap_tool.analyze import ErrorSummarizer, SecurityAuditor


def _get_tls_failure_count(metrics_data: dict) -> int:
    err_summary = metrics_data.get("error_summary", {})
    tls_fail = err_summary.get("TLS Handshake Failure")
    if isinstance(tls_fail, dict):
        return tls_fail.get("count", 0)
    return tls_fail or 0


@pytest.mark.slow
def test_failure_capture_pipeline():
    df = pd.read_csv(Path("tests/fixtures/Failure_Pcap.csv"))

    rename_map = {
        "src_ip": "source_ip",
        "dest_ip": "destination_ip",
        "src_port": "source_port",
        "dest_port": "destination_port",
        "proto": "protocol",
        "http_status": "http_response_code",
        "http_method": "http_request_method",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    field_set = set(PcapRecord.__dataclass_fields__.keys())
    records = [
        PcapRecord(**{k: row.get(k) for k in field_set})
        for row in df.to_dict(orient="records")
    ]
    stats = collect_stats(records)

    engine = HeuristicEngine('src/heuristics/rules.yaml')
    tagged = engine.tag_flows(stats['packet_df'])

    mb = MetricsBuilder(
        stats['stats_collector'],
        stats['flow_table'],
        Enricher(),
        guess_service,
        stats['performance_analyzer'],
        stats['timeline_builder'],
        ErrorSummarizer(),
        SecurityAuditor(Enricher()),
        engine,
    )

    metrics = mb.build_metrics(stats['packet_df'], tagged)

    if isinstance(engine, VectorisedHeuristicEngine):
        cause_col = tagged['flow_cause']
        assert (
            (tagged['flow_disposition'] == 'Blocked')
            & (cause_col == 'Proxy Authentication Failed')
        ).any()
        # DNS/TLS mismatch detection may label flows as "Mis-routed"
        assert (tagged['flow_disposition'] == 'Mis-routed').any()
        tls_count = _get_tls_failure_count(metrics)
        assert tls_count >= 1
    else:
        assert (
            tagged['flow_disposition']
            == 'Blocked - Proxy Authentication Failed'
        ).any()
        assert 'Mis-routed' not in tagged['flow_disposition'].values
        tls_count = _get_tls_failure_count(metrics)
        assert tls_count == 0

    plaintext_count = metrics.get('security_findings', {}).get('plaintext_http_flows', 0)
    assert plaintext_count > 0

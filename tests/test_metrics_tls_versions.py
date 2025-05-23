import pandas as pd
from pcap_tool.metrics_builder import MetricsBuilder
from pcap_tool.metrics.flow_table import FlowTable
from pcap_tool.metrics.stats_collector import StatsCollector
from pcap_tool.metrics.timeline_builder import TimelineBuilder
from pcap_tool.analyze import PerformanceAnalyzer, ErrorSummarizer, SecurityAuditor
from pcap_tool.enrichment import Enricher

class DummyServiceGuesser:
    def guess_service(self, *args, **kwargs):
        return "dummy"

class DummyHeuristic:
    pass

def test_metrics_builder_tls_version_counts():
    packet_df = pd.DataFrame([
        {"tls_effective_version": "TLS 1.2"},
        {"tls_effective_version": "TLS 1.3"},
    ])
    mb = MetricsBuilder(
        StatsCollector(),
        FlowTable(),
        Enricher(),
        DummyServiceGuesser(),
        PerformanceAnalyzer(),
        TimelineBuilder(),
        ErrorSummarizer(),
        SecurityAuditor(Enricher()),
        DummyHeuristic(),
    )
    metrics = mb.build_metrics(packet_df, pd.DataFrame())
    assert metrics["tls_version_counts"] == {"TLS 1.2": 1, "TLS 1.3": 1}

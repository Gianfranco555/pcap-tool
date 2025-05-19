import pandas as pd
from pcap_tool.metrics_builder import MetricsBuilder
from pcap_tool.analyze import ErrorSummarizer, SecurityAuditor, PerformanceAnalyzer
from pcap_tool.metrics.flow_table import FlowTable
from pcap_tool.metrics.stats_collector import StatsCollector
from pcap_tool.metrics.timeline_builder import TimelineBuilder
from pcap_tool.enrichment import Enricher


class DummyServiceGuesser:
    def guess_service(self, *args, **kwargs):
        return "dummy"


class DummyHeuristic:
    pass


class DummyEnricher(Enricher):
    def enrich_ips(self, ips):
        return {ip: {} for ip in ips}


class DummyStats(StatsCollector):
    def summary(self):
        return {"capture_info": {}, "protocols": {}, "top_ports": {}, "quic_vs_tls_packets": {}}


def test_metrics_builder_with_dest_ip_only():
    mb = MetricsBuilder(
        DummyStats(),
        FlowTable(),
        DummyEnricher(),
        DummyServiceGuesser(),
        PerformanceAnalyzer(),
        TimelineBuilder(),
        ErrorSummarizer(),
        SecurityAuditor(DummyEnricher()),
        DummyHeuristic(),
    )

    packet_df = pd.DataFrame()
    tagged_flow_df = pd.DataFrame({"dest_ip": ["1.2.3.4"], "protocol": ["TCP"], "dest_port": [80]})
    metrics = mb.build_metrics(packet_df, tagged_flow_df)
    assert metrics["service_overview"]
def test_error_summarizer_no_flow_id():
    df = pd.DataFrame({"flow_error_type": ["TYPE1", "TYPE1"]})
    result = ErrorSummarizer().summarize_errors(df)
    assert result == {"TYPE1": {"count": 2, "sample_flow_ids": []}}

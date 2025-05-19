from pathlib import Path
from pcap_tool.metrics.stats_collector import StatsCollector
from pcap_tool.parser import parse_pcap_to_df, PcapRecord


FIXTURE = Path(__file__).parent / "fixtures" / "stats_fixture.pcapng"


def test_stats_collector_basic():
    df = parse_pcap_to_df(FIXTURE, workers=0)
    sc = StatsCollector()

    for _, row in df.iterrows():
        rec = PcapRecord(**{k: row.get(k) for k in PcapRecord.__dataclass_fields__.keys()})
        sc.add(rec)

    summary = sc.summary()
    assert summary["protocols"] == {"tcp": 1, "udp": 1, "icmp": 1}
    assert summary["top_ports"] == {"tcp_443": 1, "udp_443": 1}

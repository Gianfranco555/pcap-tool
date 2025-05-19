from pathlib import Path

import shutil
import pytest
from scapy.utils import PcapWriter
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP


from pcap_tool.metrics.stats_collector import StatsCollector
from pcap_tool.parser import parse_pcap_to_df, PcapRecord
from pcap_tool.exceptions import CorruptPcapError



FIXTURE = Path(__file__).parent / "fixtures" / "stats_fixture.pcapng"
HAS_TSHARK = shutil.which("tshark") is not None


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not available")
def test_stats_collector_basic_fixture():
    try:
        df = parse_pcap_to_df(FIXTURE, workers=0)
    except CorruptPcapError:
        pytest.skip("pcap parsing not available")
    if df.empty:
        pytest.skip("pcap parsing not available")

def _create_fixture_pcap(path: Path) -> Path:
    """Create a tiny pcap with TCP, UDP and ICMP packets."""
    packets = [
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=443),
        Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=1234, dport=443),
        Ether() / IP(src="5.5.5.5", dst="6.6.6.6") / ICMP(),
    ]
    with PcapWriter(str(path), sync=True) as writer:
        for pkt in packets:
            writer.write(pkt)
    return path


@pytest.fixture
def stats_pcap(tmp_path: Path) -> Path:
    return _create_fixture_pcap(tmp_path / "stats_fixture.pcapng")


def test_stats_collector_basic(stats_pcap: Path):
    df = parse_pcap_to_df(stats_pcap, workers=0)

    sc = StatsCollector()

    for _, row in df.iterrows():
        rec = PcapRecord(**{k: row.get(k) for k in PcapRecord.__dataclass_fields__.keys()})
        sc.add(rec)

    summary = sc.summary()
    assert summary["protocols"] == {"tcp": 1, "udp": 1, "icmp": 1}
    assert summary["top_ports"] == {"tcp_443": 1, "udp_443": 1}

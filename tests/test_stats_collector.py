from pathlib import Path

import shutil
import pytest
from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder


from pcap_tool.metrics.stats_collector import StatsCollector
from pcap_tool.parser import parse_pcap_to_df
from pcap_tool.models import PcapRecord
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
        PacketFactory.tcp_packet("1.1.1.1", "2.2.2.2", 1234, 443),
        PacketFactory.udp_packet("3.3.3.3", "4.4.4.4", 1234, 443),
        PacketFactory.icmp_packet("5.5.5.5", "6.6.6.6"),
    ]
    return PcapBuilder.build(packets, path)


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

import sys
from pathlib import Path
import resource
import pytest
from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder

from pcap_tool.parser import parse_pcap


def _make_big_pcap(path: Path, count: int):
    packets = [PacketFactory.tcp_packet("10.0.0.1", "10.0.0.2", 1, 2) for _ in range(count)]
    for i, pkt in enumerate(packets):
        pkt.time = float(i)
    PcapBuilder.build(packets, path)


def _rss_mb() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return r / (1024 * 1024)
    return r / 1024


@pytest.mark.skipif(pytest.importorskip("duckdb", reason="duckdb not installed") is None, reason="duckdb not installed")
def test_duckdb_output_memory(tmp_path):
    pcap_path = tmp_path / "big.pcap"
    _make_big_pcap(pcap_path, 100_000)
    handle = parse_pcap(pcap_path, output_uri="duckdb://:memory:", workers=0)
    assert handle.count() == 100_000
    assert _rss_mb() < 500

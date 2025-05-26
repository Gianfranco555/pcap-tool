import pytest
from pathlib import Path
from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder

from pcap_tool.parser import parse_pcap_to_df
from pcap_tool.heuristics.metrics import compute_tcp_rtt_stats
from pcap_tool.analyze.performance_analyzer import PerformanceAnalyzer


def _create_pcap(packets, tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    return PcapBuilder.build(packets, p)


@pytest.fixture
def handshake_pcap(tmp_path: Path) -> Path:
    pkt1 = PacketFactory.tcp_packet("1.1.1.1", "2.2.2.2", 1234, 80, "S")
    pkt2 = PacketFactory.tcp_packet("2.2.2.2", "1.1.1.1", 80, 1234, "SA")
    pkt1.time = 1.0
    pkt2.time = 2.0
    return _create_pcap([pkt1, pkt2], tmp_path, "handshake.pcap")


@pytest.fixture
def syn_only_pcap(tmp_path: Path) -> Path:
    pkt = PacketFactory.tcp_packet("3.3.3.3", "4.4.4.4", 5555, 80, "S")
    pkt.time = 1.0
    return _create_pcap([pkt], tmp_path, "syn_only.pcap")


def test_tcp_rtt_extraction(handshake_pcap: Path):
    df = parse_pcap_to_df(str(handshake_pcap))
    assert "tcp_rtt_ms" in df.columns
    rtts = df["tcp_rtt_ms"].dropna().tolist()
    assert len(rtts) == 1
    assert 999 <= rtts[0] <= 1001


def test_syn_without_synack(syn_only_pcap: Path):
    df = parse_pcap_to_df(str(syn_only_pcap))
    assert df["tcp_rtt_ms"].dropna().empty


def test_compute_tcp_rtt_stats_empty():
    result = compute_tcp_rtt_stats([])
    assert result["samples"] == 0
    assert result["median"] is None
    assert "reason" in result


def test_collect_rtt_samples_basic(handshake_pcap: Path):
    df = parse_pcap_to_df(str(handshake_pcap))
    samples = PerformanceAnalyzer.collect_rtt_samples(df)
    assert len(samples) == 1
    assert 999 <= samples[0] <= 1001


def test_collect_rtt_samples_none(syn_only_pcap: Path):
    df = parse_pcap_to_df(str(syn_only_pcap))
    samples = PerformanceAnalyzer.collect_rtt_samples(df)
    assert samples == []

import pytest
from scapy.all import Ether, IP, TCP, PcapWriter
from pathlib import Path

from pcap_tool.parser import parse_pcap_to_df
from pcap_tool.heuristics.metrics import compute_tcp_rtt_stats
from pcap_tool.analyze.performance_analyzer import PerformanceAnalyzer


def _create_pcap(packets, tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    with PcapWriter(str(p), sync=True) as w:
        for pkt in packets:
            w.write(pkt)
    return p


@pytest.fixture
def handshake_pcap(tmp_path: Path) -> Path:
    pkt1 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80, flags="S")
    pkt2 = Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=80, dport=1234, flags="SA")
    pkt1.time = 1.0
    pkt2.time = 2.0
    return _create_pcap([pkt1, pkt2], tmp_path, "handshake.pcap")


@pytest.fixture
def syn_only_pcap(tmp_path: Path) -> Path:
    pkt = Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / TCP(sport=5555, dport=80, flags="S")
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

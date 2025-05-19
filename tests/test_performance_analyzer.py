from pcap_tool.analyze import PerformanceAnalyzer
from pcap_tool.parser import PcapRecord


def _flow_id(rec: PcapRecord, is_client: bool) -> str:
    if is_client:
        return f"{rec.source_ip}:{rec.source_port}-{rec.destination_ip}:{rec.destination_port}"
    return f"{rec.destination_ip}:{rec.destination_port}-{rec.source_ip}:{rec.source_port}"


def test_tcp_rtt_basic():
    analyzer = PerformanceAnalyzer()

    syn = PcapRecord(
        frame_number=1,
        timestamp=1.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=1234,
        destination_port=80,
        protocol="TCP",
        tcp_flags_syn=True,
        tcp_flags_ack=False,
        tcp_sequence_number=100,
    )
    sa = PcapRecord(
        frame_number=2,
        timestamp=1.2,
        source_ip="2.2.2.2",
        destination_ip="1.1.1.1",
        source_port=80,
        destination_port=1234,
        protocol="TCP",
        tcp_flags_syn=True,
        tcp_flags_ack=True,
        tcp_sequence_number=200,
        tcp_acknowledgment_number=101,
    )

    analyzer.add_packet(syn, _flow_id(syn, True), True)
    analyzer.add_packet(sa, _flow_id(sa, False), False)

    summary = analyzer.get_summary()
    rtt = summary["tcp_rtt_ms"]
    assert rtt["samples"] == 1
    assert 199 <= rtt["median"] <= 201
    assert summary["tcp_retransmission_ratio_percent"] == 0.0


def test_tcp_retransmission_ratio():
    analyzer = PerformanceAnalyzer()
    for i in range(4):
        rec = PcapRecord(
            frame_number=i + 1,
            timestamp=float(i),
            protocol="TCP",
            tcp_analysis_retransmission_flags=["retransmission"] if i == 2 else [],
        )
        analyzer.add_packet(rec, "f", True)

    summary = analyzer.get_summary()
    assert summary["tcp_retransmission_ratio_percent"] == 25.0

import pytest
from pathlib import Path
from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder

from pcap_tool.parser import parse_pcap_to_df


def _create_pcap(packets, tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    return PcapBuilder.build(packets, p)


@pytest.fixture
def error_packets_pcap(tmp_path: Path) -> Path:
    base_time = 1.0
    packets = [
        PacketFactory.icmp_packet("1.1.1.1", "2.2.2.2", icmp_type=3, code=0),
        PacketFactory.icmp_packet("1.1.1.1", "2.2.2.2", icmp_type=3, code=3),
        PacketFactory.icmp_packet("1.1.1.1", "2.2.2.2", icmp_type=11, code=0),
        PacketFactory.tcp_packet("3.3.3.3", "4.4.4.4", 1234, 80, "R"),
        PacketFactory.tcp_packet("5.5.5.5", "6.6.6.6", 5555, 80, "A"),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = base_time + i
    return _create_pcap(packets, tmp_path, "errors.pcap")


def test_detect_packet_error_dataframe(error_packets_pcap: Path):
    df = parse_pcap_to_df(str(error_packets_pcap), workers=0)
    assert "packet_error_reason" in df.columns
    assert df.iloc[0]["packet_error_reason"] == "ICMP_Destination_Unreachable"
    assert df.iloc[1]["packet_error_reason"] == "ICMP_Destination_Unreachable"
    assert df.iloc[2]["packet_error_reason"] == "ICMP_Time_Exceeded"
    assert df.iloc[3]["packet_error_reason"] == "TCP_RST_Received"
    assert df.iloc[4]["packet_error_reason"] == "no_error_detected"

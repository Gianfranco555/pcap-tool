import pytest
from pathlib import Path
from scapy.all import Ether, IP, TCP, ICMP, PcapWriter

from pcap_tool.parser import parse_pcap_to_df


def _create_pcap(packets, tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    with PcapWriter(str(p), sync=True) as w:
        for pkt in packets:
            w.write(pkt)
    return p


@pytest.fixture
def error_packets_pcap(tmp_path: Path) -> Path:
    base_time = 1.0
    pkt1 = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/ICMP(type=3, code=0)
    pkt1.time = base_time
    pkt2 = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/ICMP(type=3, code=3)
    pkt2.time = base_time + 1
    pkt3 = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/ICMP(type=11, code=0)
    pkt3.time = base_time + 2
    pkt4 = Ether()/IP(src="3.3.3.3", dst="4.4.4.4")/TCP(sport=1234, dport=80, flags="R")
    pkt4.time = base_time + 3
    pkt5 = Ether()/IP(src="5.5.5.5", dst="6.6.6.6")/TCP(sport=5555, dport=80, flags="A")
    pkt5.time = base_time + 4
    packets = [pkt1, pkt2, pkt3, pkt4, pkt5]
    return _create_pcap(packets, tmp_path, "errors.pcap")


def test_detect_packet_error_dataframe(error_packets_pcap: Path):
    df = parse_pcap_to_df(str(error_packets_pcap), workers=0)
    assert "packet_error_reason" in df.columns
    assert df.iloc[0]["packet_error_reason"] == "ICMP_Destination_Unreachable"
    assert df.iloc[1]["packet_error_reason"] == "ICMP_Destination_Unreachable"
    assert df.iloc[2]["packet_error_reason"] == "ICMP_Time_Exceeded"
    assert df.iloc[3]["packet_error_reason"] == "TCP_RST_Received"
    assert df.iloc[4]["packet_error_reason"] == "no_error_detected"

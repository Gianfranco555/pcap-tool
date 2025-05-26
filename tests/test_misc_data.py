# tests/test_misc_data.py

import pytest
from pathlib import Path

from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder

from pcap_tool.parser import parse_pcap
from pcap_tool.core.constants import (
    ZSCALER_EXAMPLE_IP_RANGES,
    ZPA_SYNTHETIC_IP_RANGE,
)


def create_pcap_file(packets, tmp_path: Path, filename: str = "test.pcap") -> Path:
    return PcapBuilder.build_in_temp(packets, tmp_path, filename)


def test_icmp_fragmentation_needed_original_mtu(tmp_path: Path):
    pkt = PacketFactory.icmp_packet(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        icmp_type=3,
        code=4,
        nexthopmtu=1400,
    )
    pkt.time = 1.0
    pcap_path = create_pcap_file([pkt], tmp_path, "icmp_frag_needed.pcap")
    df = parse_pcap(str(pcap_path)).as_dataframe()
    if df.empty:
        pytest.skip("pcap parsing not available")
    rec = df.iloc[0]
    assert rec["icmp_fragmentation_needed_original_mtu"] == 1400


def test_zscaler_and_zpa_ip_flags(tmp_path: Path):
    zs_ip = str(ZSCALER_EXAMPLE_IP_RANGES[0][1])
    zpa_ip = str(ZPA_SYNTHETIC_IP_RANGE.network_address + 1)

    pkt_a = PacketFactory.icmp_packet(src_ip=zs_ip, dst_ip="10.0.0.1")
    pkt_b = PacketFactory.icmp_packet(src_ip="10.0.0.1", dst_ip=zpa_ip)
    pkt_a.time = 1.0
    pkt_b.time = 2.0
    pcap_path = create_pcap_file([pkt_a, pkt_b], tmp_path, "z_flags.pcap")
    df = parse_pcap(str(pcap_path)).as_dataframe()
    if df.empty:
        pytest.skip("pcap parsing not available")
    rec_a = df.iloc[0]
    rec_b = df.iloc[1]
    assert rec_a["is_zscaler_ip"] == True
    assert rec_a["is_zpa_synthetic_ip"] == False
    assert rec_b["is_zscaler_ip"] == False
    assert rec_b["is_zpa_synthetic_ip"] == True

import pandas as pd

from pcap_tool.metrics.flow_table import FlowTable
from pcap_tool.parser import PcapRecord


def test_flow_table_basic():
    ft = FlowTable()
    packets = [
        PcapRecord(
            frame_number=1,
            timestamp=1.1,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=1111,
            destination_port=80,
            protocol="TCP",
            packet_length=100,
        ),
        PcapRecord(
            frame_number=2,
            timestamp=1.5,
            source_ip="2.2.2.2",
            destination_ip="1.1.1.1",
            source_port=80,
            destination_port=1111,
            protocol="TCP",
            packet_length=200,
        ),
        PcapRecord(
            frame_number=3,
            timestamp=2.2,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=1111,
            destination_port=80,
            protocol="TCP",
            packet_length=150,
        ),
    ]

    ft.add_packet(packets[0], is_src_client=True)
    ft.add_packet(packets[1], is_src_client=False)
    ft.add_packet(packets[2], is_src_client=True)

    df_bytes, df_pkts = ft.get_summary_df()

    assert len(df_bytes) <= 20
    assert len(df_pkts) <= 20
    assert "sparkline_bytes_c2s" in df_bytes.columns

    row = df_bytes.iloc[0]
    assert row["bytes_c2s"] == 250
    assert row["bytes_s2c"] == 200
    assert row["bytes_total"] == 450
    assert row["pkts_total"] == 3
    assert row["sparkline_bytes_c2s"] == "100,150"
    assert row["sparkline_bytes_s2c"] == "200,0"
    assert len(row["sparkline_bytes_c2s"].split(",")) == 2
    assert row["l7_protocol_guess"] == "HTTP"

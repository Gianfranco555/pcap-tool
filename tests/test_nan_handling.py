import math
from pcap_tool.analyze import PerformanceAnalyzer
from pcap_tool.models import PcapRecord
from pcap_tool.pipeline_app import _derive_flow_id, _flow_cache_key
from pcap_tool.metrics.flow_table import FlowTable



def test_derive_flow_id_nan_ports():
    rec = PcapRecord(
        frame_number=1,
        timestamp=0.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=math.nan,
        destination_port=math.nan,
        protocol="TCP",
    )
    assert _derive_flow_id(rec) == ("1.1.1.1", "2.2.2.2", 0, 0, "TCP")


def test_flow_cache_key_nan_ports():
    rec = PcapRecord(
        frame_number=1,
        timestamp=0.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=math.nan,
        destination_port=math.nan,
        protocol="TCP",
    )
    assert _flow_cache_key(rec) == "TCP_1.1.1.1:0_2.2.2.2:0"


def test_performance_analyzer_nan_sequence():
    analyzer = PerformanceAnalyzer()
    syn = PcapRecord(
        frame_number=1,
        timestamp=1.0,
        protocol="TCP",
        tcp_flags_syn=True,
        tcp_flags_ack=False,
        tcp_sequence_number=math.nan,
    )
    sa = PcapRecord(
        frame_number=2,
        timestamp=1.1,
        protocol="TCP",
        tcp_flags_syn=True,
        tcp_flags_ack=True,
        tcp_acknowledgment_number=math.nan,
    )
    analyzer.add_packet(syn, "flow", True)
    analyzer.add_packet(sa, "flow", False)
    assert analyzer.get_summary()["tcp_rtt_ms"]["samples"] == 0


def test_flow_table_nan_values():
    table = FlowTable()
    rec = PcapRecord(
        frame_number=1,
        timestamp=1.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=math.nan,
        destination_port=math.nan,
        packet_length=math.nan,
        protocol="TCP",
    )
    table.add_packet(rec, True)
    df, _ = table.get_summary_df()
    assert df.iloc[0]["src_port"] == 0
    assert df.iloc[0]["dest_port"] == 0

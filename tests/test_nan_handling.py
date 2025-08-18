import math
import pandas as pd
from pcap_tool.core.models import PcapRecord
from pcap_tool.pipeline_app import _derive_flow_id, _flow_cache_key
from pcap_tool.metrics.flow_table import FlowTable
from pcap_tool.analysis.performance.performance_analyzer import PerformanceAnalyzer


class AttrDict(dict):
    """A dictionary that allows attribute-style access."""
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


def test_derive_flow_id_nan_ports():
    row = AttrDict({
        "frame_number": 1,
        "timestamp": 0.0,
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "source_port": math.nan,
        "destination_port": math.nan,
        "protocol": "TCP",
    })
    rec = PcapRecord.from_parser_row(row)
    assert _derive_flow_id(rec) == ("1.1.1.1", "2.2.2.2", 0, 0, "TCP")


def test_flow_cache_key_nan_ports():
    row = AttrDict({
        "frame_number": 1,
        "timestamp": 0.0,
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "source_port": math.nan,
        "destination_port": math.nan,
        "protocol": "TCP",
        "tcp_stream_index": None,  # Explicitly set to None to avoid the TCP_STREAM path
    })
    rec = PcapRecord.from_parser_row(row)
    assert _flow_cache_key(rec) == "TCP_1.1.1.1:0_2.2.2.2:0"


def test_performance_analyzer_nan_sequence():
    analyzer = PerformanceAnalyzer()
    syn_row = AttrDict({
        "frame_number": 1,
        "timestamp": 1.0,
        "protocol": "TCP",
        "tcp_flags_syn": True,
        "tcp_flags_ack": False,
        "tcp_sequence_number": math.nan,
    })
    sa_row = AttrDict({
        "frame_number": 2,
        "timestamp": 1.1,
        "protocol": "TCP",
        "tcp_flags_syn": True,
        "tcp_flags_ack": True,
        "tcp_acknowledgment_number": math.nan,
    })
    syn = PcapRecord.from_parser_row(syn_row)
    sa = PcapRecord.from_parser_row(sa_row)
    analyzer.add_packet(syn, "flow", True)
    analyzer.add_packet(sa, "flow", False)
    assert analyzer.get_summary()["tcp_rtt_ms"]["samples"] == 0


def test_flow_table_nan_values():
    table = FlowTable()
    row = AttrDict({
        "frame_number": 1,
        "timestamp": 1.0,
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "source_port": math.nan,
        "destination_port": math.nan,
        "packet_length": math.nan,
        "protocol": "TCP",
    })
    rec = PcapRecord.from_parser_row(row)
    table.add_packet(rec, True)
    df, _ = table.get_summary_df()
    assert df.iloc[0]["src_port"] == 0
    assert df.iloc[0]["dest_port"] == 0

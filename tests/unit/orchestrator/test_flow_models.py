from pcap_tool.core.models import PcapRecord
from pcap_tool.orchestrator.flow_models import Flow


def _tcp_handshake_packets():
    return [
        PcapRecord(
            timestamp=1.0,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            tcp_flags_syn=True,
            tcp_flags_ack=False,
            packet_length=60,
        ),
        PcapRecord(
            timestamp=1.1,
            source_ip="10.0.0.2",
            destination_ip="10.0.0.1",
            source_port=80,
            destination_port=12345,
            protocol="TCP",
            tcp_flags_syn=True,
            tcp_flags_ack=True,
            packet_length=60,
        ),
        PcapRecord(
            timestamp=1.2,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            tcp_flags_syn=False,
            tcp_flags_ack=True,
            packet_length=60,
        ),
    ]


def test_flow_id_deterministic():
    packets = _tcp_handshake_packets()
    flow_a = Flow.from_packets(packets)
    flow_b = Flow.from_packets(packets)
    assert flow_a.id == flow_b.id
    assert flow_a.key == flow_b.key
    assert flow_a.id == "TCP:10.0.0.1:12345->10.0.0.2:80#1.000000"


def test_role_derivation_prefers_syn():
    packets = _tcp_handshake_packets()
    flow = Flow.from_packets(packets)
    assert flow.client_is_src is True
    assert flow.key.src_ip == "10.0.0.1"
    assert flow.key.dst_port == 80


def test_role_derivation_falls_back_to_port():
    packets = [
        PcapRecord(
            timestamp=2.0,
            source_ip="10.0.0.2",
            destination_ip="10.0.0.3",
            source_port=53,
            destination_port=15000,
            protocol="UDP",
            packet_length=50,
        ),
        PcapRecord(
            timestamp=2.1,
            source_ip="10.0.0.3",
            destination_ip="10.0.0.2",
            source_port=15000,
            destination_port=53,
            protocol="UDP",
            packet_length=50,
        ),
    ]
    flow = Flow.from_packets(packets)
    assert flow.client_is_src is False
    assert flow.key.src_ip == "10.0.0.3"
    assert flow.key.dst_port == 53


def test_role_derivation_falls_back_to_port_reverse():
    packets = [
        PcapRecord(
            timestamp=3.0,
            source_ip="10.0.0.3",
            destination_ip="10.0.0.2",
            source_port=15000,
            destination_port=53,
            protocol="UDP",
            packet_length=50,
        ),
        PcapRecord(
            timestamp=3.1,
            source_ip="10.0.0.2",
            destination_ip="10.0.0.3",
            source_port=53,
            destination_port=15000,
            protocol="UDP",
            packet_length=50,
        ),
    ]
    flow = Flow.from_packets(packets)
    assert flow.client_is_src is True
    assert flow.key.src_ip == "10.0.0.3"
    assert flow.key.dst_port == 53


def test_role_derivation_equal_ports():
    packets = [
        PcapRecord(
            timestamp=4.0,
            source_ip="10.0.0.4",
            destination_ip="10.0.0.5",
            source_port=5000,
            destination_port=5000,
            protocol="UDP",
            packet_length=40,
        ),
        PcapRecord(
            timestamp=4.1,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.4",
            source_port=5000,
            destination_port=5000,
            protocol="UDP",
            packet_length=40,
        ),
    ]
    flow = Flow.from_packets(packets)
    assert flow.client_is_src is None


def test_tcp_without_syn_falls_back_to_ports():
    packets = [
        PcapRecord(
            timestamp=5.0,
            source_ip="10.0.0.4",
            destination_ip="10.0.0.5",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            tcp_flags_syn=False,
            tcp_flags_ack=True,
            packet_length=60,
        ),
        PcapRecord(
            timestamp=5.1,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.4",
            source_port=80,
            destination_port=12345,
            protocol="TCP",
            tcp_flags_syn=False,
            tcp_flags_ack=True,
            packet_length=60,
        ),
    ]
    flow = Flow.from_packets(packets)
    assert flow.client_is_src is True
    assert flow.key.src_ip == "10.0.0.4"
    assert flow.key.dst_port == 80

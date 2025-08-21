from pcap_tool.core.models import PcapRecord
from pcap_tool.orchestrator.flow_builder import FlowBuilder


def pkt(ts, src, dst, sport, dport, flags=""):
    return PcapRecord(
        timestamp=ts,
        source_ip=src,
        destination_ip=dst,
        source_port=sport,
        destination_port=dport,
        protocol="TCP",
        packet_length=1,
        tcp_flags_syn="S" in flags,
        tcp_flags_ack="A" in flags,
        tcp_flags_fin="F" in flags,
        tcp_flags_rst="R" in flags,
    )


def collect(builder, packets):
    flows = []
    for p in packets:
        flows.extend(builder.observe(p))
    return flows


def test_fin_close_normal():
    b = FlowBuilder(timeout_s=60)
    packets = [
        pkt(0, "1.1.1.1", "2.2.2.2", 1234, 80, "S"),
        pkt(1, "2.2.2.2", "1.1.1.1", 80, 1234, "SA"),
        pkt(2, "1.1.1.1", "2.2.2.2", 1234, 80, "A"),
        pkt(3, "1.1.1.1", "2.2.2.2", 1234, 80, ""),
        pkt(10, "1.1.1.1", "2.2.2.2", 1234, 80, "F"),
        pkt(11, "2.2.2.2", "1.1.1.1", 80, 1234, "A"),
        pkt(12, "2.2.2.2", "1.1.1.1", 80, 1234, "F"),
        pkt(13, "1.1.1.1", "2.2.2.2", 1234, 80, "A"),
    ]
    flows = collect(b, packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.handshake_complete is True
    assert flow.end_ts == 13
    assert len(flow.packets) == len(packets)
    assert b.flush_all() == []


def test_rst_terminates_immediately():
    b = FlowBuilder()
    packets = [
        pkt(0, "1.1.1.1", "2.2.2.2", 1234, 80, "S"),
        pkt(1, "2.2.2.2", "1.1.1.1", 80, 1234, "R"),
    ]
    flows = collect(b, packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.handshake_complete is False
    assert flow.end_ts == 1


def test_idle_timeout_expires_flow():
    b = FlowBuilder(timeout_s=60)
    p1 = pkt(0, "1.1.1.1", "2.2.2.2", 1234, 80, "S")
    b.observe(p1)
    # Second packet belongs to another flow and is far in the future
    p2 = pkt(70, "3.3.3.3", "4.4.4.4", 5555, 80, "S")
    flows = b.observe(p2)
    # The first flow should be timed out and emitted
    assert len(flows) == 1
    flow = flows[0]
    assert flow.start_ts == 0
    assert flow.end_ts == 0
    # Flush remaining flow
    remaining = b.flush_all()
    assert len(remaining) == 1


def test_syn_only_identifies_client():
    b = FlowBuilder()
    p = pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80, "S")
    b.observe(p)
    flows = b.flush_all()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.key.client_ip == "10.0.0.1"
    assert flow.key.server_port == 80
    assert flow.handshake_complete is False

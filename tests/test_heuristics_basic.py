import pandas as pd

from pcap_tool.heuristics.engine import VectorisedHeuristicEngine


def _make_tcp_packet(ts, src_ip, dst_ip, sport, dport, flags, client=True):
    return {
        "timestamp": ts,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": sport,
        "destination_port": dport,
        "protocol": "TCP",
        "is_source_client": client,
        "tcp_flags_syn": "S" in flags,
        "tcp_flags_ack": "A" in flags,
        "tcp_flags_psh": "P" in flags,
        "tcp_flags_rst": "R" in flags,
    }


def _make_icmp_packet(ts, src_ip, dst_ip, icmp_type):
    return {
        "timestamp": ts,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": 0,
        "destination_port": 0,
        "protocol": "ICMP",
        "is_source_client": False,
        "icmp_type": icmp_type,
    }


def test_basic_dispositions():
    packets = []
    # Allowed flow
    packets.extend(
        [
            _make_tcp_packet(0.0, "1.1.1.1", "2.2.2.2", 1111, 80, "S", True),
            _make_tcp_packet(0.1, "2.2.2.2", "1.1.1.1", 80, 1111, "SA", False),
            _make_tcp_packet(0.2, "1.1.1.1", "2.2.2.2", 1111, 80, "A", True),
            _make_tcp_packet(0.3, "1.1.1.1", "2.2.2.2", 1111, 80, "P", True),
            _make_tcp_packet(0.4, "2.2.2.2", "1.1.1.1", 80, 1111, "P", False),
        ]
    )
    # Blocked flow
    packets.extend(
        [
            _make_tcp_packet(1.0, "3.3.3.3", "4.4.4.4", 2222, 22, "S", True),
            _make_tcp_packet(1.5, "4.4.4.4", "3.3.3.3", 22, 2222, "R", False),
        ]
    )
    # Degraded flow
    packets.append(_make_icmp_packet(2.0, "5.5.5.5", "6.6.6.6", 3))
    # Unknown flow
    packets.extend(
        [
            _make_tcp_packet(3.0, "7.7.7.7", "8.8.8.8", 3333, 80, "S", True),
            _make_tcp_packet(3.1, "8.8.8.8", "7.7.7.7", 80, 3333, "SA", False),
            _make_tcp_packet(3.2, "7.7.7.7", "8.8.8.8", 3333, 80, "A", True),
        ]
    )

    df = pd.DataFrame(packets)
    engine = VectorisedHeuristicEngine()
    flows = engine.tag_flows(df)

    results = {(r.flow_disposition, r.flow_cause) for r in flows.itertuples()}

    assert ("Allowed", "Completed TCP session with data exchange") in results
    assert ("Blocked", "TCP RST from destination after SYN") in results
    assert (
        "Degraded",
        "ICMP Destination Unreachable/Time Exceeded in flow",
    ) in results
    assert ("Unknown", "Undetermined") in results

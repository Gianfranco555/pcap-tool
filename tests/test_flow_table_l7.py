from pcap_tool.metrics.flow_table import FlowTable
from pcap_tool.parser import PcapRecord


def _make_record(frame, ts, sport, dport, proto):
    return PcapRecord(
        frame_number=frame,
        timestamp=ts,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=sport,
        destination_port=dport,
        protocol=proto,
        packet_length=100,
    )


def test_l7_protocol_guess_in_summary_df():
    ft = FlowTable()
    packets = [
        _make_record(1, 1.0, 1111, 80, "TCP"),
        _make_record(2, 1.1, 1111, 80, "TCP"),
        _make_record(3, 2.0, 2222, 53, "UDP"),
        _make_record(4, 2.1, 2222, 53, "UDP"),
        _make_record(5, 3.0, 3333, 443, "UDP"),
    ]

    ft.add_packet(packets[0], True)
    ft.add_packet(packets[1], True)
    ft.add_packet(packets[2], True)
    ft.add_packet(packets[3], False)
    ft.add_packet(packets[4], True)

    df_bytes, _ = ft.get_summary_df()
    assert "l7_protocol_guess" in df_bytes.columns
    guesses = set(df_bytes["l7_protocol_guess"].tolist())
    assert "HTTP" in guesses
    assert "DNS" in guesses
    assert "QUIC_UDP_443" in guesses

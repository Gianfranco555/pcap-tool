from pcap_tool.metrics.flow_table import FlowTable
from pcap_tool.models import PcapRecord


def test_flow_l7_protocol_guess():
    table = FlowTable()
    # QUIC-like UDP/443 flow
    table.add_packet(
        PcapRecord(
            frame_number=1,
            timestamp=1.0,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=12345,
            destination_port=443,
            protocol="UDP",
            packet_length=50,
        ),
        True,
    )
    # HTTP
    table.add_packet(
        PcapRecord(
            frame_number=2,
            timestamp=1.1,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.3",
            source_port=23456,
            destination_port=80,
            protocol="TCP",
            packet_length=60,
        ),
        True,
    )
    # HTTPS
    table.add_packet(
        PcapRecord(
            frame_number=3,
            timestamp=1.2,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.4",
            source_port=34567,
            destination_port=443,
            protocol="TCP",
            packet_length=60,
        ),
        True,
    )
    # DNS
    table.add_packet(
        PcapRecord(
            frame_number=4,
            timestamp=1.3,
            source_ip="1.1.1.1",
            destination_ip="8.8.8.8",
            source_port=45678,
            destination_port=53,
            protocol="UDP",
            packet_length=70,
        ),
        True,
    )

    df, _ = table.get_summary_df()
    guesses = {
        (row.dest_ip, row.dest_port): row.l7_protocol_guess
        for row in df.itertuples()
    }
    assert guesses[("2.2.2.2", 443)] == "QUIC_UDP_443"
    assert guesses[("2.2.2.3", 80)] == "HTTP"
    assert guesses[("2.2.2.4", 443)] == "HTTPS/TLS"
    assert guesses[("8.8.8.8", 53)] == "DNS"

import pandas as pd
from pcap_tool.heuristics.engine import VectorisedHeuristicEngine


def test_downstream_icmp_error_triggers_degraded():
    packets = [
        {
            "timestamp": 0.0,
            "source_ip": "1.1.1.1",
            "destination_ip": "2.2.2.2",
            "source_port": 1234,
            "destination_port": 80,
            "protocol": "TCP",
            "is_source_client": True,
            "tcp_flags_syn": True,
            "ip_id": 100,
        },
        {
            "timestamp": 1.0,
            "source_ip": "9.9.9.9",
            "destination_ip": "1.1.1.1",
            "source_port": 0,
            "destination_port": 0,
            "protocol": "ICMP",
            "icmp_type": 11,
            "icmp_code": 0,
            "icmp_original_destination_ip": "2.2.2.2",
            "icmp_original_destination_port": 80,
            "icmp_original_protocol": "TCP",
            "icmp_original_ip_id": 100,
            "is_source_client": False,
        },
    ]

    df = pd.DataFrame(packets)
    engine = VectorisedHeuristicEngine()
    flows = engine.tag_flows(df)

    target = flows.loc[flows.server_ip == "2.2.2.2"].iloc[0]
    assert target.icmp_error_count == 1
    assert target.flow_disposition == "Degraded"
    assert target.flow_cause == "Downstream ICMP errors"

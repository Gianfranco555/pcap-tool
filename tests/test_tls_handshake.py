import pandas as pd
import pytest
from pcap_tool.heuristics.engine import VectorisedHeuristicEngine
from pcap_tool.parsers.tls import get_tls_handshake_outcome


def _pkt(ts, src, dst, sport, dport, client, hs_type=None, alert=None, rst=False):
    return {
        "timestamp": ts,
        "source_ip": src,
        "destination_ip": dst,
        "source_port": sport,
        "destination_port": dport,
        "protocol": "TCP",
        "is_source_client": client,
        "tcp_flags_syn": False,
        "tcp_flags_ack": False,
        "tcp_flags_psh": False,
        "tcp_flags_rst": rst,
        "tls_handshake_type": hs_type,
        "tls_alert_message_description": alert,
    }


def test_tls_handshake_outcome_and_blocking():
    packets = [
        _pkt(0.0, "1.1.1.1", "2.2.2.2", 1111, 443, True, hs_type="ClientHello"),
        _pkt(0.1, "2.2.2.2", "1.1.1.1", 443, 1111, False, hs_type="ServerHello"),
        _pkt(1.0, "3.3.3.3", "4.4.4.4", 2222, 443, True, hs_type="ClientHello"),
        _pkt(1.2, "4.4.4.4", "3.3.3.3", 443, 2222, False, alert="handshake_failure"),
    ]
    df = pd.DataFrame(packets)

    outcome = get_tls_handshake_outcome(df)
    assert outcome.loc[0, "tls_handshake_ok"] is True
    assert outcome.loc[1, "tls_handshake_ok"] is False

    engine = VectorisedHeuristicEngine()
    flows = engine.tag_flows(df)

    fail_row = flows.loc[flows.client_ip == "3.3.3.3"].iloc[0]
    assert fail_row.tls_handshake_ok is False
    assert fail_row.flow_disposition == "Blocked"
    assert fail_row.flow_cause == "TLS Handshake Failure"
    assert fail_row.time_to_alert == pytest.approx(0.2)

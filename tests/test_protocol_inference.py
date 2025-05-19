import pandas as pd

from pcap_tool.heuristics.protocol_inference import guess_l7_protocol


def test_quic_guess():
    data = {"protocol": "UDP", "dest_port": 443}
    assert guess_l7_protocol(data) == "QUIC_UDP_443"


def test_quic_guess_src_port():
    data = {"protocol": "UDP", "src_port": 443, "dest_port": 1234}
    assert guess_l7_protocol(data) == "QUIC_UDP_443"


def test_known_tcp_port():
    data = {"protocol": "TCP", "dest_port": 22}
    assert guess_l7_protocol(data) == "SSH"


def test_unknown_fallback():
    data = {"protocol": "TCP", "dest_port": 9999}
    assert guess_l7_protocol(data) == "TCP"


def test_series_input():
    series = pd.Series({"protocol": "TCP", "dest_port": 80})
    assert guess_l7_protocol(series) == "HTTP"

import pytest

from pcap_tool.enrich.service_guesser import guess_service


def test_https_with_sni():
    assert (
        guess_service("TCP", 443, sni="example.com")
        == "example.com"
    )


def test_quic_on_443():
    assert guess_service("UDP", 443, is_quic=True) == "QUIC"


def test_imaps_table_lookup():
    assert guess_service("TCP", 993) == "IMAPS"


def test_rdns_only():
    assert guess_service("TCP", 1234, rdns="smtp.example.com") == "smtp"


def test_unknown_fallback():
    assert guess_service("TCP", 5555) == "TCP/5555"

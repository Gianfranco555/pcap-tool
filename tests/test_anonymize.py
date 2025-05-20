from pcap_tool.utils import anonymize_ip


def test_anonymize_ip_ipv4():
    assert anonymize_ip("192.168.1.42") == "192.168.1.0"


def test_anonymize_ip_ipv6():
    assert anonymize_ip("2001:db8:abcd:0::1") == "2001:db8:abcd::"

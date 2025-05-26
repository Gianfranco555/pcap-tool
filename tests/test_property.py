import ipaddress
import pytest

try:
    from hypothesis import given, strategies as st
except Exception:  # pragma: no cover - hypothesis may not be installed
    hypothesis_available = False
    def given(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    class st:
        @staticmethod
        def ip_addresses():
            return []

        @staticmethod
        def lists(*args, **kwargs):
            return []

        @staticmethod
        def binary(*args, **kwargs):
            return b""
else:
    hypothesis_available = True

from pcap_tool.utils.net import anonymize_ip
from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder


@pytest.mark.skipif(not hypothesis_available, reason="hypothesis not installed")
@given(st.ip_addresses())
def test_anonymize_ip_property(addr):
    anon = anonymize_ip(str(addr))
    net = ipaddress.ip_network(anon)
    assert addr in net
    if isinstance(addr, ipaddress.IPv4Address):
        assert net.prefixlen == 24
    else:
        assert net.prefixlen == 48


@pytest.mark.skipif(not hypothesis_available, reason="hypothesis not installed")
@given(st.lists(st.binary(min_size=1, max_size=10), min_size=1, max_size=5))
def test_pcap_builder_roundtrip(tmp_path, payloads):
    packets = [PacketFactory.udp_packet("1.1.1.1", "2.2.2.2", 1234, 53, payload=p) for p in payloads]
    path = PcapBuilder.build_in_temp(packets, tmp_path, "prop.pcap")
    from scapy.all import rdpcap

    assert len(rdpcap(str(path))) == len(payloads)


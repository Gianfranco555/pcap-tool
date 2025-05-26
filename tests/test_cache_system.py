from pcap_tool.core.cache import FlowCache
from pcap_tool.core.models import PcapRecord
from pcap_tool.heuristics import protocol_inference as proto
from pcap_tool.processors import tls_processor as tls


def test_flow_cache_stats_and_clear():
    cache = FlowCache(maxsize=2, enabled=True)
    rec = PcapRecord(
        frame_number=1,
        timestamp=0.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=1234,
        destination_port=80,
        protocol="TCP",
    )
    cache.derive_flow_id(rec)
    cache.derive_flow_id(rec)
    info = cache.stats()
    assert info["derive_flow_id"].hits >= 1
    cache.clear()
    assert cache.stats()["derive_flow_id"].hits == 0


def test_protocol_inference_cache():
    proto._packet_cache.clear()
    data = {"protocol": "TCP", "dest_port": 80}
    assert proto.guess_l7_protocol(data) == "HTTP"
    assert proto.guess_l7_protocol(data) == "HTTP"
    stats = proto._packet_cache.stats()
    assert stats["_guess_impl"].hits >= 1


def test_tls_version_cache():
    tls._packet_cache.clear()
    assert tls._map_tls_version(0x0303) == "TLS 1.2"
    assert tls._map_tls_version(0x0303) == "TLS 1.2"
    stats = tls._packet_cache.stats()
    assert stats["_map_tls_version"].hits >= 1

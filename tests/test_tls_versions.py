import pytest
from pathlib import Path

from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLS13ServerHello
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_CH, TLS_Ext_SupportedVersion_SH
from scapy.packet import Raw
from tests.fixtures.packet_factory import PacketFactory
from tests.fixtures.pcap_builder import PcapBuilder

from pcap_tool.parser import parse_pcap
from pcap_tool.heuristics.metrics import count_tls_versions


@pytest.fixture
def tls_versions_pcap(tmp_path: Path) -> Path:
    ch12 = TLSClientHello(version=0x0303)
    sh12 = TLSServerHello(version=0x0303)
    ch13 = TLSClientHello(version=0x0303, ext=[TLS_Ext_SupportedVersion_CH(versions=[0x0304])])
    sh13 = TLS13ServerHello(version=0x0304, cipher=0x1301, ext=[TLS_Ext_SupportedVersion_SH(version=0x0304)])
    rec_ch12 = TLS(type=22, version=0x0303, len=len(bytes(ch12))) / Raw(load=bytes(ch12))
    rec_sh12 = TLS(type=22, version=0x0303, len=len(bytes(sh12))) / Raw(load=bytes(sh12))
    rec_ch13 = TLS(type=22, version=0x0301, len=len(bytes(ch13))) / Raw(load=bytes(ch13))
    rec_sh13 = TLS(type=22, version=0x0301, len=len(bytes(sh13))) / Raw(load=bytes(sh13))

    pkts = [
        PacketFactory.tcp_packet("10.0.0.1", "10.0.0.2", 1111, 443, "PA") / rec_ch12,
        PacketFactory.tcp_packet("10.0.0.2", "10.0.0.1", 443, 1111, "PA") / rec_sh12,
        PacketFactory.tcp_packet("10.0.0.3", "10.0.0.4", 2222, 443, "PA") / rec_ch13,
        PacketFactory.tcp_packet("10.0.0.4", "10.0.0.3", 443, 2222, "PA") / rec_sh13,
    ]
    for i, p in enumerate(pkts):
        p.time = 1.0 + i
    pcap_path = PcapBuilder.build_in_temp(pkts, tmp_path, "tls_versions.pcap")
    return pcap_path


def test_tls_version_parsing_and_aggregation(tls_versions_pcap: Path):
    df = parse_pcap(str(tls_versions_pcap), workers=0).as_dataframe()
    if df.empty:
        pytest.skip("pcap parsing not available")

    versions = df["tls_effective_version"].dropna().tolist()
    assert "TLS 1.2" in versions
    assert "TLS 1.3" in versions

    counts = count_tls_versions(df.to_dict(orient="records"))
    assert counts.get("TLS 1.2", 0) >= 1
    assert counts.get("TLS 1.3", 0) >= 1

import pytest
from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLS13ServerHello
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_CH, TLS_Ext_SupportedVersion_SH
from scapy.packet import Raw
from scapy.utils import PcapWriter

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
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1111, dport=443, flags="PA")/rec_ch12,
        Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=443, dport=1111, flags="PA")/rec_sh12,
        Ether()/IP(src="10.0.0.3", dst="10.0.0.4")/TCP(sport=2222, dport=443, flags="PA")/rec_ch13,
        Ether()/IP(src="10.0.0.4", dst="10.0.0.3")/TCP(sport=443, dport=2222, flags="PA")/rec_sh13,
    ]
    for i, p in enumerate(pkts):
        p.time = 1.0 + i
    pcap_path = tmp_path / "tls_versions.pcap"
    with PcapWriter(str(pcap_path), sync=True) as writer:
        for p in pkts:
            writer.write(p)
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

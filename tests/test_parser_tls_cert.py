import os
import subprocess
import pytest
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, PcapWriter
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSCertificate, TLSClientHello, TLSServerHello
from pcap_tool.parser import parse_pcap


def _tshark_version_lt_4() -> bool:
    try:
        out = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=True).stdout
        for token in out.split():
            if token[0].isdigit():
                major = int(token.split(".")[0])
                return major < 4
    except Exception:
        return True
    return False


@pytest.fixture
def tls_cert_pcap(tmp_path: Path) -> Path:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:1024",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-subj",
            "/CN=test.local",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    der = subprocess.run(
        ["openssl", "x509", "-outform", "der", "-in", str(cert_path)],
        capture_output=True,
        check=True,
    ).stdout

    ch = TLSClientHello(version=0x0303)
    sh = TLSServerHello(version=0x0303)
    cert_msg = TLSCertificate(certs=[(len(der), der)])

    pkts = [
        Ether()
        / IP(src="1.1.1.1", dst="2.2.2.2")
        / TCP(sport=1234, dport=443, flags="PA")
        / TLS(type=22, version=0x0303, len=len(bytes(ch)))
        / Raw(load=bytes(ch)),
        Ether()
        / IP(src="2.2.2.2", dst="1.1.1.1")
        / TCP(sport=443, dport=1234, flags="PA")
        / TLS(type=22, version=0x0303, len=len(bytes(sh)))
        / Raw(load=bytes(sh)),
        Ether()
        / IP(src="2.2.2.2", dst="1.1.1.1")
        / TCP(sport=443, dport=1234, flags="PA")
        / TLS(type=22, version=0x0303, len=len(bytes(cert_msg)))
        / Raw(load=bytes(cert_msg)),
    ]

    pcap_path = tmp_path / "tls_cert.pcap"
    with PcapWriter(str(pcap_path), sync=True) as writer:
        for p in pkts:
            writer.write(p)
    return pcap_path


def test_tls_certificate_parsing(tls_cert_pcap: Path):
    if _tshark_version_lt_4():
        pytest.skip("tshark < 4.0")

    df = parse_pcap(str(tls_cert_pcap)).as_dataframe()
    if df.empty:
        pytest.skip("pcap parsing not available")

    rows = df[df["tls_cert_subject_cn"].notna()]
    if rows.empty:
        pytest.skip("certificate metadata unavailable")

    rec = rows.iloc[0]
    assert rec["tls_cert_subject_cn"] is not None
    # Certificate expiration may be unavailable; default to None
    assert rec["tls_cert_not_after"] is None
    assert rec["tls_cert_is_self_signed"] is not None
    if rec["tls_cert_san_dns"] is not None:
        assert isinstance(rec["tls_cert_san_dns"], list)

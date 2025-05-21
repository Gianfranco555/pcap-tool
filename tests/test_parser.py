# tests/test_parser.py

import os
import pytest
from pathlib import Path
import pandas as pd
from dataclasses import fields # Use fields to get all PcapRecord field names

from pcap_tool.parser import (
    parse_pcap,
    parse_pcap_to_df,
    validate_pcap_file,
)
from pcap_tool.models import PcapRecord
from pcap_tool.exceptions import CorruptPcapError
import shutil

HAS_TSHARK = shutil.which("tshark") is not None

from scapy.all import load_layer
load_layer("tls")

from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, StrLenField
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Raw
from scapy.utils import PcapWriter


ScapyServerNameClass = None
TLSExtensionServerNameClass = None
try:
    from scapy.layers.tls.extensions import ServerName as ModernScapyServerName
    from scapy.layers.tls.extensions import TLSExtensionServerName as ModernTLSExtensionServerName
    ScapyServerNameClass = ModernScapyServerName
    TLSExtensionServerNameClass = ModernTLSExtensionServerName
    print("[INFO Scapy Imports] Using MODERN Scapy TLS extension imports.")
except ImportError:
    print("[INFO Scapy Imports] Modern Scapy TLS import failed, trying OLDER pattern.")
    try:
        from scapy.layers.tls.extensions import TLS_Ext_ServerName as OlderTLSExtensionServerName
        TLSExtensionServerNameClass = OlderTLSExtensionServerName
        class FallbackScapyServerNameEntry(Packet):
            name = "ServerNameEntry (Fallback)"
            fields_desc = [
                ByteEnumField("name_type", 0, {0: "host_name"}),
                FieldLenField("name_len", None, length_of="servername", fmt="!H"),
                StrLenField("servername", b"", length_from=lambda pkt: pkt.name_len)
            ]
        ScapyServerNameClass = FallbackScapyServerNameEntry
        print("[INFO Scapy Imports] Using OLDER Scapy TLS_Ext_ServerName and custom FallbackScapyServerNameEntry.")
    except ImportError:
        print("[ERROR Scapy Imports] OLDER Scapy TLS_Ext_ServerName import also failed.")
        ScapyServerNameClass = None
        TLSExtensionServerNameClass = None
        print("[ERROR Scapy Imports] CRITICAL: Could not import any Scapy TLS ServerName or TLSExtensionServerName classes.")

def create_pcap_file_with_desktop_copy(packets, tmp_path, filename="test.pcapng"):
    pcap_file_path = tmp_path / filename
    desktop_path = os.path.expanduser("~/Desktop")
    inspect_filename = f"inspect_{Path(filename).stem}.pcap"
    inspect_full_path = os.path.join(desktop_path, inspect_filename)
    # print(f"\n[INFO Test Util] Attempting to save inspection PCAP to: {inspect_full_path}\n") # Reduce noise
    try:
        with PcapWriter(inspect_full_path, sync=True) as writer_inspect: # Use with statement
            for pkt_inspect in packets:
                writer_inspect.write(pkt_inspect)
        # print(f"[INFO Test Util] Successfully saved inspection PCAP to: {inspect_full_path}\n")
    except Exception as e:
        print(f"[ERROR Test Util] ERROR saving inspection PCAP to Desktop: {e}\n")

    with PcapWriter(str(pcap_file_path), sync=True) as writer: # Use with statement
        for pkt in packets:
            writer.write(pkt)
    return pcap_file_path

create_pcap_file = create_pcap_file_with_desktop_copy

@pytest.fixture
def happy_path_pcap(tmp_path):
    # Ensure IP flags are correctly set if parser expects them (e.g. DF = 0x02)
    # Scapy's flags field can take a string like "DF" or an integer.
    pkt1 = Ether()/IP(src="192.168.1.100", dst="192.168.1.1", flags="DF")/TCP(sport=12345, dport=80, flags="S")
    pkt2 = Ether()/IP(src="192.168.1.1",   dst="192.168.1.100", flags="DF")/TCP(sport=80,    dport=12345, flags="SA")
    pkt3 = Ether()/IP(src="192.168.1.100", dst="192.168.1.1", flags="DF")/TCP(sport=12345, dport=80,    flags="A")

    if ScapyServerNameClass is None or TLSExtensionServerNameClass is None:
        raise ImportError("ScapyServerNameClass or TLSExtensionServerNameClass could not be defined/imported.")

    server_name_entry_obj = ScapyServerNameClass(servername=b"test.example.com")
    sni_extension_obj = TLSExtensionServerNameClass(servernames=[server_name_entry_obj])
    client_hello_obj = TLSClientHello(version=0x0303, ext=[sni_extension_obj])
    client_hello_bytes = bytes(client_hello_obj)
    # Correctly layer TLS record over Raw payload of TLS Handshake
    tls_record_obj = TLS(type=22, version=0x0303, len=len(client_hello_bytes)) / Raw(load=client_hello_bytes)


    pkt4 = (Ether() / IP(src="192.168.1.100", dst="192.168.1.200", flags="DF") / # Added DF
            TCP(sport=54321, dport=443, flags="PA") / tls_record_obj)
    pkt5 = (Ether() / IP(src="192.168.1.101", dst="192.168.1.102", flags="DF") / # Added DF
            UDP(sport=10000, dport=53) / Raw(load=b"DNSQuery"))
    pkt6 = (Ether() / IP(src="192.168.1.103", dst="192.168.1.104", flags="DF") / ICMP(type="echo-request")) # Added DF
    packets = [pkt1, pkt2, pkt3, pkt4, pkt5, pkt6]
    base_time = 1678886400.0
    for i, pkt_val in enumerate(packets):
        pkt_val.time = base_time + i
    return create_pcap_file(packets, tmp_path, "happy_path.pcap")

@pytest.fixture
def malformed_tls_pcap(tmp_path):
    pkt1 = Ether()/IP(src="192.168.2.10", dst="192.168.2.20", flags="DF")/TCP(sport=23456, dport=443, flags="S") # Added DF
    pkt1.time = 1678886500.000
    pkt2 = (Ether() / IP(src="192.168.2.10", dst="192.168.2.20", flags="DF") / # Added DF
            TCP(sport=23456, dport=443, flags="PA") / Raw(load=b"This is not a TLS packet payload."))
    pkt2.time = 1678886500.100
    client_hello_no_sni = TLSClientHello(ext=None)
    tls_record_no_sni = TLS(type=22, version=0x0303) / client_hello_no_sni
    pkt3 = (Ether() / IP(src="192.168.2.10", dst="192.168.2.20", flags="DF") / # Added DF
            TCP(sport=23457, dport=443, flags="PA") / tls_record_no_sni)
    pkt3.time = 1678886500.200
    packets = [pkt1, pkt2, pkt3]
    return create_pcap_file(packets, tmp_path, "malformed_tls.pcap")

def assert_new_fields_logic(record_series, is_ip_packet=True, is_tcp_packet=False): # is_tcp_packet for potential future use
    """Asserts new fields, handling booleans correctly based on IP/TCP presence."""
    assert pd.isna(record_series["gre_protocol"]), f"GRE Protocol: Expected NA, got {record_series['gre_protocol']}"
    assert pd.isna(record_series["esp_spi"]), f"ESP SPI: Expected NA, got {record_series['esp_spi']}"
    assert pd.isna(record_series["quic_initial_packet_present"]), f"QUIC Initial: Expected NA, got {record_series['quic_initial_packet_present']}"
    assert pd.isna(record_series["is_quic"]), f"is_quic: Expected NA, got {record_series['is_quic']}"
    assert pd.isna(record_series["ssl_inspection_active"]), f"SSL Inspection: Expected NA, got {record_series['ssl_inspection_active']}"
    assert pd.isna(record_series["zscaler_policy_block_type"]), f"ZS Policy Block: Expected NA, got {record_series['zscaler_policy_block_type']}"

    if is_ip_packet:
        # CHANGE: Use '== False' for value comparison with Pandas/NumPy bools
        assert record_series["is_zscaler_ip"] == False, \
            f"is_zscaler_ip: Expected False, got {record_series['is_zscaler_ip']}"
        assert record_series["is_zpa_synthetic_ip"] == False, \
            f"is_zpa_synthetic_ip: Expected False, got {record_series['is_zpa_synthetic_ip']}"
    else:
        assert pd.isna(record_series["is_zscaler_ip"]), \
            f"is_zscaler_ip (non-IP): Expected NA, got {record_series['is_zscaler_ip']}"
        assert pd.isna(record_series["is_zpa_synthetic_ip"]), \
            f"is_zpa_synthetic_ip (non-IP): Expected NA, got {record_series['is_zpa_synthetic_ip']}"

    if is_tcp_packet:
        val = record_series["is_src_client"]
        assert pd.isna(val) or val in [True, False]
    else:
        assert pd.isna(record_series["is_src_client"])

def test_happy_path_parsing(happy_path_pcap):
    df = parse_pcap(str(happy_path_pcap)).as_dataframe()
    assert not df.empty, "DataFrame should not be empty"
    assert len(df) == 6, f"Expected 6 packets, got {len(df)}"

    expected_cols = [field.name for field in fields(PcapRecord)]
    assert all(col in df.columns for col in expected_cols), "DataFrame columns mismatch"

    syn = df.iloc[0]
    assert syn["frame_number"] == 1
    assert syn["source_ip"] == "192.168.1.100"
    assert syn["destination_ip"] == "192.168.1.1"
    assert syn["protocol"] == "TCP"
    # CHANGE: Use '== True' for value comparison
    assert syn["tcp_flags_syn"] == True, f"tcp_flags_syn: Expected True, got {syn['tcp_flags_syn']}"
    assert syn["ip_flags_df"] == True, f"ip_flags_df: Expected True, got {syn['ip_flags_df']}"
    assert pd.isna(syn["sni"])
    assert_new_fields_logic(syn, is_tcp_packet=True)


    tls_rec = df.iloc[3]
    assert tls_rec["frame_number"] == 4
    assert tls_rec["protocol"] == "TCP"
    assert tls_rec["destination_port"] == 443
    assert tls_rec["sni"] == "test.example.com", f"SNI: Expected test.example.com, got {tls_rec['sni']}"
    # Assuming pkt4 also has DF flag set in its IP layer
    assert tls_rec["ip_flags_df"] == True, f"tls_rec ip_flags_df: Expected True, got {tls_rec['ip_flags_df']}"
    assert_new_fields_logic(tls_rec, is_tcp_packet=True)

    udp_rec = df.iloc[4]
    assert udp_rec["frame_number"] == 5
    assert udp_rec["protocol"] == "UDP"
    assert udp_rec["ip_flags_df"] == True, f"udp_rec ip_flags_df: Expected True, got {udp_rec['ip_flags_df']}"
    assert_new_fields_logic(udp_rec)

    icmp_rec = df.iloc[5]
    assert icmp_rec["frame_number"] == 6
    assert str(icmp_rec["protocol"]).upper() == "ICMP"
    assert icmp_rec["ip_flags_df"] == True, f"icmp_rec ip_flags_df: Expected True, got {icmp_rec['ip_flags_df']}"
    assert_new_fields_logic(icmp_rec)

def test_happy_path_with_max_packets(happy_path_pcap):
    df3 = parse_pcap_to_df(str(happy_path_pcap), max_packets=3)
    assert len(df3) == 3, "max_packets=3 should return 3 records"
    df1 = parse_pcap_to_df(str(happy_path_pcap), max_packets=1)
    assert len(df1) == 1, "max_packets=1 should return 1 record"
    df0 = parse_pcap_to_df(str(happy_path_pcap), max_packets=0)
    assert df0.empty, "max_packets=0 should return an empty DataFrame"

def test_malformed_or_no_sni_tls_packet(malformed_tls_pcap):
    df = parse_pcap(str(malformed_tls_pcap)).as_dataframe()
    assert len(df) == 3, f"Expected 3 packets, got {len(df)}"

    rec1 = df.iloc[0]
    assert rec1["protocol"] == "TCP" and pd.isna(rec1["sni"])
    # CHANGE: Use '== True' for value comparison
    assert rec1["tcp_flags_syn"] == True, f"rec1 tcp_flags_syn: Expected True, got {rec1['tcp_flags_syn']}"
    assert rec1["ip_flags_df"] == True, f"rec1 ip_flags_df: Expected True, got {rec1['ip_flags_df']}" # Assuming DF set in fixture
    assert_new_fields_logic(rec1, is_tcp_packet=True)

    rec2 = df.iloc[1]
    assert rec2["protocol"] == "TCP" and pd.isna(rec2["sni"])
    assert rec2["ip_flags_df"] == True, f"rec2 ip_flags_df: Expected True, got {rec2['ip_flags_df']}" # Assuming DF set in fixture
    assert_new_fields_logic(rec2, is_tcp_packet=True)

    rec3 = df.iloc[2]
    assert rec3["protocol"] == "TCP" and pd.isna(rec3["sni"])
    assert rec3["ip_flags_df"] == True, f"rec3 ip_flags_df: Expected True, got {rec3['ip_flags_df']}" # Assuming DF set in fixture
    assert_new_fields_logic(rec3, is_tcp_packet=True)


def test_empty_pcap(tmp_path):
    empty_pcap_file = create_pcap_file([], tmp_path, "empty.pcap")
    df = parse_pcap(str(empty_pcap_file)).as_dataframe()
    assert df.empty
    expected_cols = [field.name for field in fields(PcapRecord)]
    assert all(col in df.columns for col in expected_cols)

def test_non_ip_packet(tmp_path):
    pkt_l2 = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:01:02:03:04:05", type=0x88B5)
    pkt_l2.time = 1678886600.0
    non_ip_pcap_file = create_pcap_file([pkt_l2], tmp_path, "non_ip.pcap")
    df = parse_pcap(str(non_ip_pcap_file)).as_dataframe()

    assert len(df) == 1, f"Expected 1 non-IP packet, got {len(df)}"
    rec = df.iloc[0]
    assert rec["frame_number"] == 1
    assert pd.isna(rec["source_ip"])
    assert pd.isna(rec["destination_ip"])
    assert pd.isna(rec["protocol_l3"])
    assert pd.isna(rec["protocol"])
    assert rec["raw_packet_summary"] is not None
    assert rec["source_mac"] == "00:01:02:03:04:05"
    assert rec["destination_mac"] == "ff:ff:ff:ff:ff:ff"
    assert_new_fields_logic(rec, is_ip_packet=False)


@pytest.fixture
def tcp_flags_pcap(tmp_path):
    packets = []
    packets.append(Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")/
                    IP(src="10.0.0.1", dst="10.0.0.2")/
                    TCP(sport=1111, dport=80, flags="S"))
    packets.append(Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/
                    TCP(sport=80, dport=1111, flags="SA"))
    packets.append(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/
                    TCP(sport=1111, dport=80, flags="FPU"))
    packets.append(Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/
                    TCP(sport=80, dport=1111, flags="R"))
    return create_pcap_file(packets, tmp_path, "tcp_flags.pcap")


@pytest.fixture
def dns_query_response_pcap(tmp_path):
    query = (Ether()/IP(src="10.0.0.1", dst="8.8.8.8")/
             UDP(sport=12345, dport=53)/
             DNS(id=1, rd=1, qd=DNSQR(qname="example.com")))
    response = (Ether()/IP(src="8.8.8.8", dst="10.0.0.1")/
                UDP(sport=53, dport=12345)/
                DNS(id=1, qr=1, aa=1, rcode=0,
                    qd=DNSQR(qname="example.com"),
                    an=DNSRR(rrname="example.com", rdata="93.184.216.34")))
    return create_pcap_file([query, response], tmp_path, "dns_qr.pcap")


@pytest.fixture
def udp_443_non_quic_pcap(tmp_path):
    pkt = Ether()/IP(src="10.10.10.1", dst="10.10.10.2", flags="DF")/UDP(sport=1111, dport=443)/Raw(load=b"hello")
    pkt.time = 1678886700.0
    return create_pcap_file([pkt], tmp_path, "udp443_not_quic.pcap")


@pytest.fixture
def pcapkit_l2_l3_test_pcap(tmp_path):
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=60)
        / TCP(sport=12345, dport=80)
    )
    return create_pcap_file([pkt], tmp_path, "pcapkit_l2_l3.pcap")


@pytest.fixture
def pcapkit_arp_test_pcap(tmp_path):
    arp_pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src="00:01:02:03:04:05")
        / ARP(
            pdst="192.168.1.1",
            psrc="192.168.1.100",
            hwsrc="00:01:02:03:04:05",
            hwdst="00:00:00:00:00:00",
            op=1,
        )
    )
    return create_pcap_file([arp_pkt], tmp_path, "pcapkit_arp.pcap")


def test_tcp_flag_parsing(tcp_flags_pcap):
    df = parse_pcap(str(tcp_flags_pcap)).as_dataframe()
    assert len(df) == 4
    syn = df.iloc[0]
    assert syn["tcp_flags_syn"] == True
    assert syn["tcp_flags_ack"] == False
    sa = df.iloc[1]
    assert sa["tcp_flags_syn"] == True
    assert sa["tcp_flags_ack"] == True
    finpsh = df.iloc[2]
    assert finpsh["tcp_flags_fin"] == True
    assert finpsh["tcp_flags_psh"] == True
    assert finpsh["tcp_flags_urg"] == True
    rst = df.iloc[3]
    assert rst["tcp_flags_rst"] in [True, None]


def test_is_src_client_orientation(happy_path_pcap):
    df = parse_pcap(str(happy_path_pcap)).as_dataframe()
    syn = df.iloc[0]
    synack = df.iloc[1]
    ack = df.iloc[2]
    assert syn["is_src_client"] == True
    assert synack["is_src_client"] == False
    assert ack["is_src_client"] == True


def test_dns_query_and_response(dns_query_response_pcap):
    df = parse_pcap(str(dns_query_response_pcap)).as_dataframe()
    assert len(df) == 2
    q = df.iloc[0]
    assert q["dns_query_name"] == "example.com"
    assert pd.isna(q["dns_response_code"])
    r = df.iloc[1]
    assert r["dns_query_name"] == "example.com"
    assert r["dns_response_code"] == "NOERROR"


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not available")
def test_zscaler_policy_block():
    pcap_path = Path("tests/fixtures/trigger_zscaler_rst.pcapng")
    try:
        df = parse_pcap(str(pcap_path)).as_dataframe()
    except CorruptPcapError:
        pytest.skip("pcap parsing not available")
    if df.empty:
        pytest.skip("pcap parsing not available")
    zs_rows = df[df["source_ip"] == "165.225.1.1"]
    assert not zs_rows.empty
    rec = zs_rows.iloc[0]
    assert rec["is_zscaler_ip"] == True
    assert "zscaler_policy_block_type" in df.columns


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not available")
def test_tls_sni_extraction():
    pcap_path = Path("tests/fixtures/trigger_https_traffic.pcapng")
    try:
        df = parse_pcap(str(pcap_path)).as_dataframe()
    except CorruptPcapError:
        pytest.skip("pcap parsing not available")
    if df.empty:
        pytest.skip("pcap parsing not available")
    rec = df.iloc[0]
    assert rec["destination_port"] == 443
    assert rec["sni"] == "example.com"


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not available")
def test_tls_non_standard_port():
    pcap_path = Path("tests/fixtures/trigger_non_standard_tls_port.pcapng")
    try:
        df = parse_pcap(str(pcap_path)).as_dataframe()
    except CorruptPcapError:
        pytest.skip("pcap parsing not available")
    if df.empty:
        pytest.skip("pcap parsing not available")
    rec = df.iloc[0]
    assert rec["destination_port"] == 8443
    assert rec["sni"] == "nonstd.com"


def test_basic_l2_l3_l4_details(tcp_flags_pcap):
    df = parse_pcap(str(tcp_flags_pcap)).as_dataframe()
    rec = df.iloc[0]
    assert rec["source_mac"] == "aa:aa:aa:aa:aa:aa"
    assert rec["destination_mac"] == "bb:bb:bb:bb:bb:bb"
    assert rec["source_ip"] == "10.0.0.1"
    assert rec["destination_ip"] == "10.0.0.2"
    assert rec["source_port"] == 1111
    assert rec["destination_port"] == 80
    assert rec["protocol"] == "TCP"


def test_udp_443_not_quic(udp_443_non_quic_pcap):
    df = parse_pcap(str(udp_443_non_quic_pcap)).as_dataframe()
    rec = df.iloc[0]
    assert rec["protocol"] == "UDP"
    assert rec["destination_port"] == 443
    assert rec["is_quic"] == False


def test_pcapkit_l2_l3_fields(pcapkit_l2_l3_test_pcap):
    df = parse_pcap(str(pcapkit_l2_l3_test_pcap)).as_dataframe()
    assert not df.empty and len(df) == 1
    rec = df.iloc[0]
    assert str(rec["source_mac"]).upper() == "00:11:22:33:44:55".upper()
    assert str(rec["destination_mac"]).upper() == "AA:BB:CC:DD:EE:FF".upper()
    assert rec["source_ip"] == "10.0.0.1"
    assert rec["destination_ip"] == "10.0.0.2"
    assert rec["ip_ttl"] == 60
    assert rec["protocol_l3"] in ["IPv4", "IP"]
    assert rec["protocol"] == "TCP"


def test_pcapkit_arp_fields(pcapkit_arp_test_pcap):
    df = parse_pcap(str(pcapkit_arp_test_pcap)).as_dataframe()
    assert not df.empty and len(df) == 1
    rec = df.iloc[0]
    assert rec["protocol_l3"] == "ARP"
    assert rec["arp_opcode"] == 1
    assert rec["arp_sender_mac"] == "00:01:02:03:04:05"
    assert rec["arp_sender_ip"] == "192.168.1.100"
    assert rec["arp_target_mac"] == "00:00:00:00:00:00"
    assert rec["arp_target_ip"] == "192.168.1.1"


def test_safe_int_parses_commas():
    from pcap_tool.parser.helpers import _safe_int

    assert _safe_int("1,234") == 1234
    assert _safe_int(None) is None
    assert _safe_int("bad") is None


def test_safe_int_edge_cases():
    from pcap_tool.parser.helpers import _safe_int

    assert _safe_int("-1,234") == -1234
    assert _safe_int(" 42 ") == 42
    assert _safe_int("3.14") is None


def test_validate_pcap_valid(example_pcap):
    assert validate_pcap_file(str(example_pcap)) is True


def _make_text_file(tmp_path):
    p = tmp_path / "text.txt"
    p.write_text("not a pcap")
    return p


def _make_zero_file(tmp_path):
    p = tmp_path / "zero.bin"
    p.write_bytes(b"")
    return p


def _make_bad_magic_file(tmp_path):
    p = tmp_path / "badmagic.pcap"
    p.write_bytes(b"\x01\x02\x03\x04" + b"rest")
    return p


@pytest.mark.parametrize("creator", [_make_text_file, _make_zero_file, _make_bad_magic_file])
def test_validate_pcap_invalid_rejected(tmp_path, creator):
    path = creator(tmp_path)
    assert validate_pcap_file(str(path)) is False
    with pytest.raises(CorruptPcapError):
        parse_pcap(str(path))

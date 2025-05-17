# tests/test_parser.py

import os
import pytest
from pathlib import Path
import pandas as pd
from dataclasses import asdict

# Import the PcapRecord and parse_pcap function from your pcap_tool
from pcap_tool.parser import parse_pcap, PcapRecord

# ── Scapy imports ────────────────────────────────────────────────────────────
from scapy.all import load_layer
load_layer("tls") # Ensures TLS layers are loaded

from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, StrLenField
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Raw
from scapy.utils import wrpcap, PcapWriter

# --- START: Scapy TLS Extension Imports (KEEP THIS LOGIC AS IS) ---
# This block handles Scapy version differences for TLS extensions.
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
# --- END: Scapy TLS Extension Imports ---


# --- Option 1: create_pcap_file WITH saving to Desktop (for temporary inspection) ---
# If you want to keep saving the inspect_happy_path.pcap to your Desktop for a bit:
def create_pcap_file_with_desktop_copy(packets, tmp_path, filename="test.pcapng"):
    """Creates a PCAP file in tmp_path and a copy on the Desktop."""
    pcap_file_path = tmp_path / filename

    # Save a copy to the Desktop for manual inspection
    desktop_path = os.path.expanduser("~/Desktop")
    # Use a more specific name if happy_path_pcap calls this with a different filename argument
    inspect_filename = f"inspect_{Path(filename).stem}.pcap" 
    inspect_full_path = os.path.join(desktop_path, inspect_filename)
    print(f"\n[INFO Test Util] Attempting to save inspection PCAP to: {inspect_full_path}\n")
    try:
        writer_inspect = PcapWriter(inspect_full_path, sync=True)
        for pkt_inspect in packets:
            writer_inspect.write(pkt_inspect)
        writer_inspect.close()
        print(f"[INFO Test Util] Successfully saved inspection PCAP to: {inspect_full_path}\n")
    except Exception as e:
        print(f"[ERROR Test Util] ERROR saving inspection PCAP to Desktop: {e}\n")

    # Original writer for the test's temp path
    writer = PcapWriter(str(pcap_file_path), sync=True)
    for pkt in packets:
        writer.write(pkt)
    writer.close()
    return pcap_file_path

# --- Option 2: create_pcap_file WITHOUT saving to Desktop (standard for committed tests) ---
# This is the version you'd typically keep for committed code.
def create_pcap_file_standard(packets, tmp_path, filename="test.pcapng"):
    """Creates a PCAP file in tmp_path with the given Scapy packets."""
    pcap_file_path = tmp_path / filename
    writer = PcapWriter(str(pcap_file_path), sync=True)
    for pkt in packets:
        writer.write(pkt)
    writer.close()
    return pcap_file_path

# --- CHOOSE WHICH create_pcap_file to use ---
# To use the version that saves to Desktop:
create_pcap_file = create_pcap_file_with_desktop_copy
# To use the standard version (no Desktop copy):
# create_pcap_file = create_pcap_file_standard


@pytest.fixture
def happy_path_pcap(tmp_path):
    """PCAP with TCP, TLS w/ SNI, UDP, ICMP packets."""
    pkt1 = Ether()/IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="S")
    pkt2 = Ether()/IP(src="192.168.1.1",   dst="192.168.1.100")/TCP(sport=80,    dport=12345, flags="SA")
    pkt3 = Ether()/IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=12345, dport=80,    flags="A")

    if ScapyServerNameClass is None or TLSExtensionServerNameClass is None:
        # This print is still useful if imports fail in a different environment
        print("[ERROR Fixture Setup] CRITICAL: ScapyServerNameClass or TLSExtensionServerNameClass was not successfully defined/imported.")
        raise ImportError("ScapyServerNameClass or TLSExtensionServerNameClass could not be defined/imported. Check Scapy installation and version.")

    # TLS Client Hello with SNI
    server_name_entry_obj = ScapyServerNameClass(servername=b"test.example.com")
    sni_extension_obj = TLSExtensionServerNameClass(servernames=[server_name_entry_obj])
    client_hello_obj = TLSClientHello(version=0x0303, ext=[sni_extension_obj]) # TLS 1.2
    
    client_hello_bytes = bytes(client_hello_obj)
    client_hello_len = len(client_hello_bytes)

    # Create the TLS record, explicitly setting its length and payload
    tls_record_obj = TLS(type=22, version=0x0303) # type=22 for handshake, version for TLS 1.2
    tls_record_obj.len = client_hello_len        
    tls_record_obj.payload = Raw(load=client_hello_bytes)

    pkt4 = (
        Ether()
        / IP(src="192.168.1.100", dst="192.168.1.200")
        / TCP(sport=54321, dport=443, flags="PA") # PSH, ACK
        / tls_record_obj 
    )

    # UDP packet
    pkt5 = ( Ether() / IP(src="192.168.1.101", dst="192.168.1.102") / UDP(sport=10000, dport=53) / Raw(load=b"DNSQuery") )
    
    # ICMP packet
    pkt6 = ( Ether() / IP(src="192.168.1.103", dst="192.168.1.104") / ICMP(type="echo-request") )

    packets = [pkt1, pkt2, pkt3, pkt4, pkt5, pkt6]
    base_time = 1678886400.0 # Example timestamp
    for i, pkt_val in enumerate(packets):
        pkt_val.time = base_time + i
    
    # Ensure the fixture calls the chosen create_pcap_file function
    return create_pcap_file(packets, tmp_path, "happy_path.pcap")


@pytest.fixture
def malformed_tls_pcap(tmp_path):
    """PCAP with TCP on 443: non-TLS payload and TLS without SNI."""
    pkt1 = Ether()/IP(src="192.168.2.10", dst="192.168.2.20")/TCP(sport=23456, dport=443, flags="S")
    pkt1.time = 1678886500.000

    pkt2 = (
        Ether()
        / IP(src="192.168.2.10", dst="192.168.2.20")
        / TCP(sport=23456, dport=443, flags="PA")
        / Raw(load=b"This is not a TLS packet payload.")
    )
    pkt2.time = 1678886500.100

    client_hello_no_sni = TLSClientHello(ext=None) # No extensions means no SNI
    # Added type and version for consistency, Scapy should calculate length
    tls_record_no_sni   = TLS(type=22, version=0x0303) / client_hello_no_sni 
    pkt3 = (
        Ether()
        / IP(src="192.168.2.10", dst="192.168.2.20")
        / TCP(sport=23457, dport=443, flags="PA")
        / tls_record_no_sni
    )
    pkt3.time = 1678886500.200

    packets = [pkt1, pkt2, pkt3]
    return create_pcap_file(packets, tmp_path, "malformed_tls.pcap")


def test_happy_path_parsing(happy_path_pcap):
    """Tests parsing of a well-formed PCAP with various protocols including TLS SNI."""
    df = parse_pcap(str(happy_path_pcap))
    assert not df.empty, "DataFrame should not be empty for happy_path_pcap"
    assert len(df) == 6, "Should parse all 6 packets from happy_path_pcap"

    expected_cols = list(asdict(PcapRecord(frame_number=0, timestamp=0.0, source_ip="dummy")).keys())
    assert all(col in df.columns for col in expected_cols), "DataFrame columns do not match PcapRecord schema"

    # TCP SYN (frame 1)
    syn = df.iloc[0]
    assert syn["frame_number"] == 1
    assert syn["source_ip"] == "192.168.1.100"
    assert syn["destination_ip"] == "192.168.1.1"
    assert syn["source_port"] == 12345
    assert syn["destination_port"] == 80
    assert syn["protocol"] == "TCP"
    assert pd.isna(syn["sni"]), "SNI should be NaN for non-TLS packets"

    # TLS ClientHello w/ SNI (frame 4)
    tls_record_from_df = df.iloc[3]
    assert tls_record_from_df["frame_number"] == 4
    assert tls_record_from_df["source_ip"] == "192.168.1.100"
    assert tls_record_from_df["destination_ip"] == "192.168.1.200"
    assert tls_record_from_df["source_port"] == 54321
    assert tls_record_from_df["destination_port"] == 443
    assert tls_record_from_df["protocol"] == "TCP"
    assert tls_record_from_df["sni"] == "test.example.com", f"Expected SNI 'test.example.com' but got '{tls_record_from_df['sni']}'"

    # UDP (frame 5)
    udp = df.iloc[4]
    assert udp["frame_number"] == 5
    assert udp["protocol"] == "UDP"
    assert udp["source_port"] == 10000
    assert udp["destination_port"] == 53
    assert pd.isna(udp["sni"])

    # ICMP (frame 6)
    icmp = df.iloc[5]
    assert icmp["frame_number"] == 6
    assert str(icmp["protocol"]).upper() in ("ICMP", "1"), f"Unexpected protocol for ICMP: {icmp['protocol']}"
    assert pd.isna(icmp["source_port"]) or icmp["source_port"] == 0 
    assert pd.isna(icmp["destination_port"]) or icmp["destination_port"] == 0
    assert pd.isna(icmp["sni"])


def test_happy_path_with_max_packets(happy_path_pcap):
    """Tests the max_packets limiting feature."""
    df3 = parse_pcap(str(happy_path_pcap), max_packets=3)
    assert len(df3) == 3, "max_packets=3 should return 3 records"

    df1 = parse_pcap(str(happy_path_pcap), max_packets=1)
    assert len(df1) == 1, "max_packets=1 should return 1 record"
    assert df1.iloc[0]["source_ip"] == "192.168.1.100"

    df0 = parse_pcap(str(happy_path_pcap), max_packets=0)
    assert df0.empty, "max_packets=0 should return an empty DataFrame"


def test_malformed_or_no_sni_tls_packet(malformed_tls_pcap):
    """Tests parsing of packets that are TCP/443 but not valid TLS ClientHello with SNI."""
    df = parse_pcap(str(malformed_tls_pcap))
    assert len(df) == 3, "Should parse all 3 packets from malformed_tls_pcap"

    rec1 = df.iloc[0] # TCP SYN
    assert rec1["frame_number"] == 1
    assert rec1["protocol"] == "TCP"
    assert rec1["destination_port"] == 443
    assert pd.isna(rec1["sni"])

    rec2 = df.iloc[1] # TCP with non-TLS Raw data
    assert rec2["frame_number"] == 2
    assert rec2["protocol"] == "TCP"
    assert rec2["destination_port"] == 443
    assert pd.isna(rec2["sni"])
    assert rec2["raw_packet_summary"] is not None

    rec3 = df.iloc[2] # TLS ClientHello but NO SNI extension
    assert rec3["frame_number"] == 3
    assert rec3["protocol"] == "TCP"
    assert rec3["destination_port"] == 443
    assert pd.isna(rec3["sni"])


def test_empty_pcap(tmp_path):
    """Tests parsing an empty PCAP file."""
    empty_pcap_file = create_pcap_file([], tmp_path, "empty.pcap")
    df = parse_pcap(str(empty_pcap_file))
    assert df.empty
    expected_cols = list(asdict(PcapRecord(frame_number=0, timestamp=0.0)).keys())
    assert all(col in df.columns for col in expected_cols)
    assert len(df) == 0


def test_non_ip_packet(tmp_path):
    """Tests parsing a PCAP with only non-IP packets (e.g., ARP)."""
    pkt_arp = ( Ether(dst="ff:ff:ff:ff:ff:ff", src="00:01:02:03:04:05") / Raw(load=b"\x00\x01\x08\x00\x06\x04\x00\x01PAYLOADARP") )
    pkt_arp.time = 1678886600.0

    non_ip_pcap_file = create_pcap_file([pkt_arp], tmp_path, "non_ip.pcap")
    df = parse_pcap(str(non_ip_pcap_file))

    assert len(df) == 1
    rec = df.iloc[0]
    assert rec["frame_number"] == 1
    assert pd.isna(rec["source_ip"])
    assert pd.isna(rec["destination_ip"])
    assert pd.isna(rec["protocol"])
    assert pd.isna(rec["source_port"])
    assert pd.isna(rec["destination_port"])
    assert pd.isna(rec["sni"])
    assert rec["raw_packet_summary"] is not None
    assert "L2:" in rec["raw_packet_summary"] or "ARP" in str(rec["raw_packet_summary"]).upper() or "ETH" in str(rec["raw_packet_summary"]).upper()
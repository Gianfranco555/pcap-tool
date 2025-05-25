"""Centralized constant definitions for pcap_tool."""

from __future__ import annotations


# ---------------------------------------------------------------------------
# PCAP file magic numbers used for basic validation
# ---------------------------------------------------------------------------
MAGIC_PCAP_LE: bytes = b"\xd4\xc3\xb2\xa1"  # Little-endian PCAP
MAGIC_PCAP_BE: bytes = b"\xa1\xb2\xc3\xd4"  # Big-endian PCAP
MAGIC_PCAPNG: bytes = b"\x0a\x0d\x0d\x0a"  # PCAPNG format

# Example IP ranges used in ICMP heuristics and tests
import ipaddress

ZSCALER_EXAMPLE_IP_RANGES = [
    ipaddress.ip_network("104.129.192.0/20"),
    ipaddress.ip_network("165.225.0.0/17"),
]

ZPA_SYNTHETIC_IP_RANGE = ipaddress.ip_network("100.64.0.0/10")


__all__ = [
    "MAGIC_PCAP_LE",
    "MAGIC_PCAP_BE",
    "MAGIC_PCAPNG",
    "ZSCALER_EXAMPLE_IP_RANGES",
    "ZPA_SYNTHETIC_IP_RANGE",
]

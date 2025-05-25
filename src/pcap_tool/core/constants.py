"""Centralized constant definitions for pcap_tool."""

from __future__ import annotations


# ---------------------------------------------------------------------------
# PCAP file magic numbers used for basic validation
# ---------------------------------------------------------------------------
MAGIC_PCAP_LE: bytes = b"\xd4\xc3\xb2\xa1"  # Little-endian PCAP
MAGIC_PCAP_BE: bytes = b"\xa1\xb2\xc3\xd4"  # Big-endian PCAP
MAGIC_PCAPNG: bytes = b"\x0a\x0d\x0d\x0a"  # PCAPNG format


__all__ = [
    "MAGIC_PCAP_LE",
    "MAGIC_PCAP_BE",
    "MAGIC_PCAPNG",
]

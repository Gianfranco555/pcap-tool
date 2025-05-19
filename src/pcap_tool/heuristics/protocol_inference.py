"""Utilities for inferring L7 protocols from flow metadata."""

from __future__ import annotations

from typing import Mapping, Any
import pandas as pd


# Mapping of (L4 protocol, port) -> well-known application protocol
_WELL_KNOWN_PORTS: dict[tuple[str, int], str] = {
    ("TCP", 20): "FTP",
    ("TCP", 21): "FTP",
    ("TCP", 22): "SSH",
    ("TCP", 23): "Telnet",
    ("TCP", 25): "SMTP",
    ("TCP", 53): "DNS",
    ("UDP", 53): "DNS",
    ("TCP", 80): "HTTP",
    ("TCP", 110): "POP3",
    ("TCP", 143): "IMAP",
    ("TCP", 443): "HTTPS/TLS",
}


def _to_int(value: Any) -> int | None:
    """Return ``int(value)`` if possible else ``None``."""
    if pd.isna(value):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def guess_l7_protocol(flow_data: Mapping[str, Any]) -> str:
    """Return a best guess at the L7 protocol for ``flow_data``.

    Parameters
    ----------
    flow_data:
        A mapping or object behaving like a dict containing at least
        ``protocol`` and ``dest_port`` or ``destination_port`` keys. ``src_port``
        is consulted for QUIC detection.
    """

    protocol = str(flow_data.get("protocol", "")).upper()
    dest_port = _to_int(
        flow_data.get("dest_port", flow_data.get("destination_port"))
    )
    src_port = _to_int(
        flow_data.get("src_port", flow_data.get("source_port"))
    )

    # --- QUIC detection on UDP/443 ---
    if protocol == "UDP" and (dest_port == 443 or src_port == 443):
        first_size = _to_int(
            flow_data.get("first_flight_bytes")
            or flow_data.get("first_flight_packet_size")
        )
        if first_size is not None and first_size > 1200:
            return "QUIC"
        return "QUIC_UDP_443"

    # --- Lookup table for other well-known ports ---
    port = dest_port if dest_port is not None else src_port
    if port is not None:
        guess = _WELL_KNOWN_PORTS.get((protocol, port))
        if guess:
            return guess

    return protocol if protocol else "Unknown_L7"

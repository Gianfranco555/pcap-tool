"""Utilities for mapping protocol/port context to friendly service names."""

from __future__ import annotations

from typing import Optional

# Minimal set of well-known ports for service guessing
WELL_KNOWN_PORTS: dict[tuple[str, int], str] = {
    ("TCP", 80): "HTTP",
    ("TCP", 443): "HTTPS",
    ("TCP", 22): "SSH",
    ("TCP", 993): "IMAPS",
    ("TCP", 465): "SMTPS",
    ("UDP", 53): "DNS",
}


def guess_service(
    protocol: Optional[str],
    port: Optional[int],
    *,
    sni: Optional[str] = None,
    http_host: Optional[str] = None,
    rdns: Optional[str] = None,
    is_quic: bool = False,
) -> str:
    """Return a human friendly service label for the given connection info."""

    # 1. Explicit host information from SNI or HTTP Host header
    if sni:
        return sni
    if http_host:
        return http_host

    # 2. QUIC traffic on the HTTPS port
    if is_quic and port == 443:
        return "QUIC"

    # 3. Lookup based on well-known ports
    if protocol and port is not None:
        service = WELL_KNOWN_PORTS.get((protocol.upper(), port))
        if service:
            return service

    # 4. Prefix from rDNS name if available
    if rdns:
        prefix = rdns.split(".")[0]
        if prefix:
            return prefix

    # 5. Fallback generic label
    if protocol and port is not None:
        return f"{protocol.upper()}/{port}"
    return "Unknown Service"

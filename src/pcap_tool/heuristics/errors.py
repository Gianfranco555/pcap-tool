from __future__ import annotations

from typing import Mapping, Any


def detect_packet_error(packet_data: Mapping[str, Any]) -> str:
    """Return a simple classification of packet level network errors.

    Parameters
    ----------
    packet_data:
        Mapping with packet fields such as ``protocol``, ``icmp_type``,
        ``icmp_code`` and ``tcp_flags_rst``.
    """
    protocol = str(packet_data.get("protocol") or "").upper()
    icmp_type = packet_data.get("icmp_type")
    icmp_code = packet_data.get("icmp_code")
    tcp_rst = packet_data.get("tcp_flags_rst")

    try:
        icmp_type_int = int(icmp_type) if icmp_type is not None else None
    except (TypeError, ValueError):
        icmp_type_int = None
    try:
        icmp_code_int = int(icmp_code) if icmp_code is not None else None
    except (TypeError, ValueError):
        icmp_code_int = None

    if protocol == "ICMP":
        if icmp_type_int == 3 and icmp_code_int in {0, 1, 2, 3}:
            return "ICMP_Destination_Unreachable"
        if icmp_type_int == 11:
            return "ICMP_Time_Exceeded"

    if protocol == "TCP" and bool(tcp_rst):
        return "TCP_RST_Received"

    return "no_error_detected"

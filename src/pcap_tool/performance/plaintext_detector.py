from __future__ import annotations

from typing import Iterable, Mapping, Any

import pandas as pd


def _is_plain_packet(pkt: Mapping[str, Any]) -> bool:
    """Return True if packet ``pkt`` is likely plaintext HTTP."""
    proto = str(pkt.get("protocol") or pkt.get("proto") or "").upper()
    method = str(pkt.get("http_request_method") or pkt.get("http_method") or "").upper()

    if proto == "HTTP" and method == "CONNECT":
        return True

    if proto == "HTTP":
        return True

    port = pkt.get("destination_port") or pkt.get("dest_port")
    try:
        port_int = int(port) if port is not None else None
    except (TypeError, ValueError):
        port_int = None
    if proto == "TCP" and port_int == 80:
        http_method = method or str(pkt.get("http_request_method") or "").upper()
        if http_method:
            return True
    return False


def count_plaintext_http_flows(records: Iterable[Mapping[str, Any]]) -> int:
    """Return number of unique flows containing plaintext HTTP packets."""
    flows = set()
    for pkt in records:
        if _is_plain_packet(pkt):
            src_ip = pkt.get("source_ip") or pkt.get("src_ip")
            dst_ip = pkt.get("destination_ip") or pkt.get("dest_ip")
            src_port = pkt.get("source_port") or pkt.get("src_port")
            dst_port = pkt.get("destination_port") or pkt.get("dest_port")
            proto = str(pkt.get("protocol") or pkt.get("proto") or "").upper()
            flows.add((src_ip, dst_ip, src_port, dst_port, proto))
    return len(flows)


def count_plaintext_http_flows_df(df: pd.DataFrame) -> int:
    """Convenience wrapper accepting a DataFrame."""
    return count_plaintext_http_flows(df.to_dict(orient="records"))

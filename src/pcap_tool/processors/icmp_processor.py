from __future__ import annotations

import ipaddress
from typing import Dict, Any, Optional, TYPE_CHECKING

from ..models import PcapRecord
from ..parsers.utils import _safe_int
from . import PacketProcessor

if TYPE_CHECKING:
    from ..parsers.pyshark_parser import PacketExtractor

ZSCALER_EXAMPLE_IP_RANGES = [
    ipaddress.ip_network("104.129.192.0/20"),
    ipaddress.ip_network("165.225.0.0/17"),
]

ZPA_SYNTHETIC_IP_RANGE = ipaddress.ip_network("100.64.0.0/10")


def _check_ip_in_ranges(ip_str: Optional[str], ranges: list[ipaddress._BaseNetwork]) -> bool:
    if not ip_str:
        return False
    try:
        ip_addr = ipaddress.ip_address(ip_str)
        for net_range in ranges:
            if ip_addr in net_range:
                return True
    except ValueError:
        return False
    return False


class ICMPProcessor(PacketProcessor):
    """Extract ICMP metadata and related IP heuristics."""

    def reset(self) -> None:  # pragma: no cover - stateless
        return None

    def process_packet(self, extractor: "PacketExtractor", record: PcapRecord) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        layer_name = None
        if record.protocol == "ICMP" and hasattr(extractor.packet, "icmp"):
            layer_name = "icmp"
        elif record.protocol == "ICMPv6" and hasattr(extractor.packet, "icmpv6"):
            layer_name = "icmpv6"

        if layer_name is not None:
            result["icmp_type"] = _safe_int(extractor.get(layer_name, "type", record.frame_number))
            result["icmp_code"] = _safe_int(extractor.get(layer_name, "code", record.frame_number))
            frag_needed_v4 = record.protocol == "ICMP" and result.get("icmp_type") == 3 and result.get("icmp_code") == 4
            pkt_too_big_v6 = record.protocol == "ICMPv6" and result.get("icmp_type") == 2 and result.get("icmp_code") == 0
            if frag_needed_v4 or pkt_too_big_v6:
                mtu_str = extractor.get(layer_name, "mtu", record.frame_number)
                if mtu_str is None and frag_needed_v4:
                    mtu_str = extractor.get(layer_name, "nexthopmtu", record.frame_number)
                if mtu_str is not None:
                    result["icmp_fragmentation_needed_original_mtu"] = _safe_int(mtu_str)

        if record.source_ip is None and record.destination_ip is None:
            result["is_zscaler_ip"] = None
            result["is_zpa_synthetic_ip"] = None
        else:
            result["is_zscaler_ip"] = (
                _check_ip_in_ranges(record.source_ip, ZSCALER_EXAMPLE_IP_RANGES)
                or _check_ip_in_ranges(record.destination_ip, ZSCALER_EXAMPLE_IP_RANGES)
            )
            result["is_zpa_synthetic_ip"] = (
                _check_ip_in_ranges(record.source_ip, [ZPA_SYNTHETIC_IP_RANGE])
                or _check_ip_in_ranges(record.destination_ip, [ZPA_SYNTHETIC_IP_RANGE])
            )
        return {k: v for k, v in result.items() if v is not None}


__all__ = [
    "ICMPProcessor",
    "ZSCALER_EXAMPLE_IP_RANGES",
    "ZPA_SYNTHETIC_IP_RANGE",
]

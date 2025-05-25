from __future__ import annotations

from typing import Dict, Any, Optional, TYPE_CHECKING

from ..core.models import PcapRecord
from ..parsers.utils import _safe_int
from . import PacketProcessor

if TYPE_CHECKING:
    from ..parsers.pyshark_parser import PacketExtractor

DNS_QUERY_TYPE_MAP: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    255: "ANY",
    257: "CAA",
}

DNS_RCODE_MAP: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DHCP_MESSAGE_TYPE_MAP: Dict[int, str] = {
    1: "Discover",
    2: "Offer",
    3: "Request",
    4: "Decline",
    5: "Ack",
    6: "Nak",
    7: "Release",
    8: "Inform",
}


class DNSProcessor(PacketProcessor):
    """Extract DNS query and response information."""

    def reset(self) -> None:  # pragma: no cover - stateless
        return None

    def process_packet(self, extractor: "PacketExtractor", record: PcapRecord) -> Dict[str, Any]:
        if not hasattr(extractor.packet, "dns"):
            return {}
        result: Dict[str, Any] = {}
        result["dns_query_name"] = extractor.get("dns", "qry_name", record.frame_number)
        qry_type = extractor.get("dns", "qry_type", record.frame_number)
        if qry_type is not None:
            result["dns_query_type"] = DNS_QUERY_TYPE_MAP.get(_safe_int(qry_type), str(qry_type))
        if extractor.get("dns", "flags_response", record.frame_number, is_flag=True):
            rcode = extractor.get("dns", "flags_rcode", record.frame_number)
            if rcode is not None:
                result["dns_response_code"] = DNS_RCODE_MAP.get(_safe_int(rcode), str(rcode))
            addrs: list[str] = []
            for field in ["a", "aaaa"]:
                if hasattr(extractor.packet.dns, field):
                    val = getattr(extractor.packet.dns, field)
                    if isinstance(val, list):
                        addrs.extend(str(v.show) if hasattr(v, "show") else str(v) for v in val)
                    elif isinstance(val, str):
                        addrs.extend([a.strip() for a in val.split(",") if a.strip()])
                    else:
                        addrs.append(str(val.show) if hasattr(val, "show") else str(val))
            if addrs:
                result["dns_response_addresses"] = addrs
            if hasattr(extractor.packet.dns, "cname"):
                cname_val = getattr(extractor.packet.dns, "cname")
                if hasattr(cname_val, "show"):
                    result["dns_response_cname_target"] = str(cname_val.show)
                else:
                    result["dns_response_cname_target"] = str(cname_val)
        return {k: v for k, v in result.items() if v is not None}


__all__ = [
    "DNSProcessor",
    "DNS_QUERY_TYPE_MAP",
    "DNS_RCODE_MAP",
    "DHCP_MESSAGE_TYPE_MAP",
]

from __future__ import annotations

from typing import Dict, Any, TYPE_CHECKING

from ..core.models import PcapRecord
from ..parsers.utils import _safe_int
from . import PacketProcessor

if TYPE_CHECKING:
    from ..parsers.pyshark_parser import PacketExtractor


class HTTPProcessor(PacketProcessor):
    """Extract HTTP request and response details."""

    def reset(self) -> None:  # pragma: no cover - stateless
        return None

    def process_packet(self, extractor: "PacketExtractor", record: PcapRecord) -> Dict[str, Any]:
        if not hasattr(extractor.packet, "http"):
            return {}
        result: Dict[str, Any] = {}
        if hasattr(extractor.packet.http, "request_method"):
            result["http_request_method"] = extractor.get("http", "request_method", record.frame_number)
            result["http_request_uri"] = extractor.get("http", "request_uri", record.frame_number)
            result["http_request_host_header"] = extractor.get("http", "host", record.frame_number)
            result["http_x_forwarded_for_header"] = extractor.get("http", "x_forwarded_for", record.frame_number)
        else:
            code = extractor.get("http", "response_code", record.frame_number)
            if code is not None:
                result["http_response_code"] = _safe_int(code)
            result["http_response_location_header"] = extractor.get("http", "location", record.frame_number)
        return {k: v for k, v in result.items() if v is not None}


__all__ = ["HTTPProcessor"]

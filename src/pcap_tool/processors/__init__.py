from __future__ import annotations

from typing import Protocol, Any, TYPE_CHECKING, Dict

from ..models import PcapRecord

if TYPE_CHECKING:  # pragma: no cover - type hints only
    from ..parsers.pyshark_parser import PacketExtractor


class PacketProcessor(Protocol):
    """Protocol for packet processing helpers."""

    def process_packet(self, extractor: "PacketExtractor", record: PcapRecord) -> Dict[str, Any]:
        """Process a packet and return extracted values."""

    def reset(self) -> None:
        """Reset any internal state."""


from .tcp_processor import TCPProcessor
from .tls_processor import TLSProcessor
from .dns_processor import DNSProcessor
from .http_processor import HTTPProcessor
from .icmp_processor import ICMPProcessor

__all__ = [
    "PacketProcessor",
    "TCPProcessor",
    "TLSProcessor",
    "DNSProcessor",
    "HTTPProcessor",
    "ICMPProcessor",
]

from __future__ import annotations

from typing import Any, Generator, Optional, TYPE_CHECKING

from pcap_tool.logging import get_logger
from ..core.models import PcapRecord
from ..core.dependencies import container

from ..processors import (
    PacketProcessor,
    TCPProcessor,
    TLSProcessor,
    DNSProcessor,
    HTTPProcessor,
    ICMPProcessor,
)
from functools import wraps
from .base import BaseParser
from .utils import _safe_int, _safe_str_to_bool
from ..core.decorators import handle_parse_errors, log_performance

logger = get_logger(__name__)

try:  # pragma: no cover - optional dependency check
    pyshark = container.get("pyshark")  # type: ignore
    USE_PYSHARK = True
except ImportError:
    USE_PYSHARK = False
    pyshark = None  # type: ignore

if TYPE_CHECKING:  # pragma: no cover - hint for static analyzers
    from pyshark.packet.packet import Packet as PySharkPacket


class PySharkParser(BaseParser):
    """Parser implementation using :mod:`pyshark` with helper methods."""

    def __init__(self, *, load_timeout: int = 5) -> None:
        """Initialize the parser.

        ``load_timeout`` sets the default timeout (in seconds) used when
        loading packets via :mod:`pyshark`.
        """

        self.load_timeout = load_timeout
        self.processors: list[PacketProcessor] = [
            TCPProcessor(),
            TLSProcessor(),
            DNSProcessor(),
            HTTPProcessor(),
            ICMPProcessor(),
        ]

    @classmethod
    def validate(cls) -> bool:  # pragma: no cover - simple availability check
        return USE_PYSHARK

    def _create_capture(
        self,
        file_path: str,
        *,
        start: int = 0,
        slice_size: Optional[int] = None,
        load_timeout: Optional[int] = None,
    ) -> "pyshark.FileCapture":
        """Create and return a configured ``pyshark.FileCapture``.

        ``load_timeout`` overrides the parser's default timeout when provided.
        """

        display_filter = None
        if start or slice_size:
            end = start + (slice_size or 0)
            if slice_size is not None:
                display_filter = f"frame.number>={start + 1} && frame.number<={end}"
            else:
                display_filter = f"frame.number>={start + 1}"

        logger.debug("PyShark display_filter set to: %s", display_filter)

        cap = pyshark.FileCapture(
            file_path,
            use_json=False,
            include_raw=False,
            keep_packets=False,
            display_filter=display_filter,
            custom_parameters=[
                "-o",
                "tls.desegment_ssl_records:TRUE",
                "-o",
                "tls.desegment_ssl_application_data:TRUE",
            ],
        )
        try:
            cap.load_packets(timeout=load_timeout or self.load_timeout)
        except Exception:
            logger.exception("Failed to load packets from %s", file_path)
        return cap

    def _packet_to_record(self, packet: "PySharkPacket") -> PcapRecord:
        """Convert a ``pyshark`` packet to :class:`PcapRecord`."""
        ts = float(packet.sniff_timestamp)
        frame_number = _safe_int(packet.number) or 0

        # Create a dictionary of the parsed data
        row_data = {
            "frame_number": frame_number,
            "timestamp": ts,
            "raw_packet_summary": str(getattr(packet, "highest_layer", "")),
        }

        # The concept of a PacketExtractor is still useful, so we create it here.
        # This avoids passing the raw packet to every processor.
        class PacketExtractor:
            def __init__(self, packet: "PySharkPacket") -> None:
                self.packet = packet

            def get(self, layer: str, attr: str, frame_number: int, *, is_flag: bool = False) -> Any:
                if not hasattr(self.packet, layer):
                    return None
                layer_obj = getattr(self.packet, layer)
                raw_value = getattr(layer_obj, attr, None)
                if is_flag:
                    return _safe_str_to_bool(raw_value)
                return raw_value
        extractor = PacketExtractor(packet)
        self._extract_layer_data(packet, row_data)

        # Create a temporary record for processors that might need it for now.
        # This can be refactored later.
        temp_record = PcapRecord(**row_data)

        for proc in self.processors:
            data = proc.process_packet(extractor, temp_record)
            row_data.update(data)

        # Use a simple object to pass to the factory method because it expects attribute access
        class AttrDict(dict):
            def __init__(self, *args, **kwargs):
                super(AttrDict, self).__init__(*args, **kwargs)
                self.__dict__ = self

        return PcapRecord.from_parser_row(AttrDict(row_data))

    def _extract_layer_data(self, packet: "PySharkPacket", record_dict: dict[str, Any]) -> None:
        """Populate L2/L3/L4 fields on ``record_dict``."""
        record_dict["packet_length"] = _safe_int(getattr(packet, "length", None))

        if hasattr(packet, "eth"):
            record_dict["source_mac"] = getattr(packet.eth, "src", None)
            record_dict["destination_mac"] = getattr(packet.eth, "dst", None)

        # Add L4 port info if available
        if hasattr(packet, "tcp"):
            record_dict["source_port"] = _safe_int(getattr(packet.tcp, "srcport", None))
            record_dict["destination_port"] = _safe_int(getattr(packet.tcp, "dstport", None))
        elif hasattr(packet, "udp"):
            record_dict["source_port"] = _safe_int(getattr(packet.udp, "srcport", None))
            record_dict["destination_port"] = _safe_int(getattr(packet.udp, "dstport", None))

        if hasattr(packet, "ip"):
            record_dict["protocol_l3"] = "IPv4"
            record_dict["source_ip"] = getattr(packet.ip, "src", None)
            record_dict["destination_ip"] = getattr(packet.ip, "dst", None)
            record_dict["ip_ttl"] = _safe_int(getattr(packet.ip, "ttl", None))
            record_dict["ip_flags_df"] = _safe_str_to_bool(getattr(packet.ip, "flags_df", "0"))
            proto = _safe_int(getattr(packet.ip, "proto", None))
            record_dict["protocol"] = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}.get(proto, str(proto) if proto is not None else None)
        elif hasattr(packet, "ipv6"):
            record_dict["protocol_l3"] = "IPv6"
            record_dict["source_ip"] = getattr(packet.ipv6, "src", None)
            record_dict["destination_ip"] = getattr(packet.ipv6, "dst", None)
            record_dict["ip_ttl"] = _safe_int(getattr(packet.ipv6, "hlim", None))
            proto = _safe_int(getattr(packet.ipv6, "nxt", None))
            record_dict["protocol"] = {6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}.get(proto, str(proto) if proto is not None else None)
        elif hasattr(packet, "arp"):
            record_dict["protocol_l3"] = "ARP"
            record_dict["arp_opcode"] = _safe_int(getattr(packet.arp, "opcode", None))
            record_dict["arp_sender_mac"] = getattr(packet.arp, "src_hw_mac", None)
            record_dict["arp_sender_ip"] = getattr(packet.arp, "src_proto_ipv4", None)
            record_dict["arp_target_mac"] = getattr(packet.arp, "dst_hw_mac", None)
            record_dict["arp_target_ip"] = getattr(packet.arp, "dst_proto_ipv4", None)


    @handle_parse_errors
    @log_performance
    def parse(
        self,
        file_path: str,
        max_packets: Optional[int],
        *,
        start: int = 0,
        slice_size: Optional[int] = None,
    ) -> Generator[PcapRecord, None, None]:
        """Yield :class:`PcapRecord` objects for ``file_path``."""
        # Reset processor state before parsing
        for proc in self.processors:
            proc.reset()

        logger.info(f"Starting PCAP parsing with PyShark for: {file_path}")

        cap = self._create_capture(
            file_path,
            start=start,
            slice_size=slice_size,
            load_timeout=self.load_timeout,
        )

        generated_records = 0
        try:
            for packet in cap:
                if max_packets is not None and generated_records >= max_packets:
                    logger.info(
                        f"PySharkParser: Reached max_packets limit of {max_packets}."
                    )
                    break

                try:
                    record = self._packet_to_record(packet)
                    yield record
                    generated_records += 1
                except Exception as exc:  # pragma: no cover - runtime protection
                    logger.error("Error processing packet: %s", exc, exc_info=True)
        finally:
            if cap:
                cap.close()
            logger.info(
                f"PySharkParser: Finished processing. Yielded {generated_records} records."
            )


# Backwards compatibility: old name with lowercase "s"
PysharkParser = PySharkParser

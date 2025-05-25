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


def _get_pyshark_layer_attribute(layer: Any, attribute_name: str, frame_number_for_log: int, is_flag: bool = False) -> Any:
    """Helper to safely get an attribute from a pyshark layer."""
    if not hasattr(layer, attribute_name):
        return None

    raw_value = getattr(layer, attribute_name)

    if is_flag:
        bool_val = _safe_str_to_bool(raw_value)
        if bool_val is None and raw_value is not None:
            logger.warning(
                f"Frame {frame_number_for_log}: Could not convert flag '{attribute_name}' with value '{raw_value}' to bool. Using None."
            )
        return bool_val

    return raw_value


def _extract_sni_pyshark(packet: "pyshark.packet.packet.Packet") -> Optional[str]:
    logger.debug(f"Frame {packet.number}: Attempting SNI extraction (V_FIXED_ACCESS).")
    sni_value = None
    try:
        if not hasattr(packet, "tls"):
            return None
        top_tls_layer = packet.tls
        if hasattr(top_tls_layer, "_all_fields"):
            logger.debug(
                f"Frame {packet.number}: Fields in top_tls_layer (packet.tls): {top_tls_layer._all_fields}"
            )
        record_data = None
        if hasattr(top_tls_layer, "tls_record"):
            record_data = top_tls_layer.tls_record
        elif "tls.record" in top_tls_layer.field_names:
            record_data = top_tls_layer.get_field_value("tls.record")
        else:
            if hasattr(top_tls_layer, "tls_handshake"):
                record_data = top_tls_layer
        if not record_data:
            if hasattr(top_tls_layer, "handshake_extensions_server_name"):
                sni_value = top_tls_layer.handshake_extensions_server_name
            return sni_value
        handshake_data = None
        if hasattr(record_data, "tls_handshake"):
            handshake_data = record_data.tls_handshake
        elif "tls.handshake" in record_data.field_names:
            handshake_data = record_data.get_field_value("tls.handshake")
        else:
            return sni_value
        if not handshake_data:
            return sni_value
        extension_data = None
        if hasattr(handshake_data, "tls_handshake_extension"):
            extension_data = handshake_data.tls_handshake_extension
        elif "tls.handshake.extension" in handshake_data.field_names:
            extension_data = handshake_data.get_field_value("tls.handshake.extension")
        else:
            return sni_value
        if not extension_data:
            return sni_value
        extensions_to_check = []
        if isinstance(extension_data, list):
            extensions_to_check.extend(extension_data)
        else:
            extensions_to_check.append(extension_data)
        for ext_entry in extensions_to_check:
            if hasattr(ext_entry, "server_name_indication_extension"):
                sni_details_obj = ext_entry.server_name_indication_extension
                if hasattr(sni_details_obj, "extensions_server_name"):
                    sni_value = sni_details_obj.extensions_server_name
                    break
                elif hasattr(sni_details_obj, "tls_handshake_extensions_server_name"):
                    sni_value = sni_details_obj.tls_handshake_extensions_server_name
                    break
        if isinstance(sni_value, list):
            sni_value = sni_value[0] if sni_value else None
    except Exception as e:  # pragma: no cover - best effort only
        logger.error(f"Frame {packet.number}: General exception in _extract_sni_pyshark: {e}", exc_info=True)
        sni_value = None
    if sni_value is None:
        logger.debug(f"Frame {packet.number}: Final SNI extraction resulted in None.")
    else:
        logger.info(f"Frame {packet.number}: Final SNI value determined: {sni_value}")
    return sni_value




class PacketExtractor:
    """Lightweight helper for extracting fields from a pyshark packet."""

    def __init__(self, packet: "PySharkPacket") -> None:
        """Store the packet reference.

        The type is annotated as a string so importing this module does not
        require :mod:`pyshark` to be installed.
        """
        self.packet = packet

    def get(self, layer: str, attr: str, frame_number: int, *, is_flag: bool = False) -> Any:
        if not hasattr(self.packet, layer):
            return None
        layer_obj = getattr(self.packet, layer)
        return _get_pyshark_layer_attribute(layer_obj, attr, frame_number, is_flag)


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
        record = PcapRecord(frame_number=frame_number, timestamp=ts, raw_packet_summary=str(getattr(packet, "highest_layer", "")))
        extractor = PacketExtractor(packet)
        self._extract_layer_data(extractor, record)
        for proc in self.processors:
            data = proc.process_packet(extractor, record)
            for key, value in data.items():
                setattr(record, key, value)
        return record

    def _extract_layer_data(self, ext: PacketExtractor, record: PcapRecord) -> None:
        """Populate L2/L3/L4 fields on ``record``."""

        record.packet_length = _safe_int(getattr(ext.packet, "length", None))

        record.source_mac = ext.get("eth", "src", record.frame_number)
        record.destination_mac = ext.get("eth", "dst", record.frame_number)

        if hasattr(ext.packet, "ip"):
            record.protocol_l3 = "IPv4"
            record.source_ip = ext.get("ip", "src", record.frame_number)
            record.destination_ip = ext.get("ip", "dst", record.frame_number)
            record.ip_ttl = _safe_int(ext.get("ip", "ttl", record.frame_number))
            record.ip_flags_df = ext.get("ip", "flags_df", record.frame_number, is_flag=True)
            proto = _safe_int(ext.get("ip", "proto", record.frame_number))
            record.protocol = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}.get(proto, str(proto) if proto is not None else None)
        elif hasattr(ext.packet, "ipv6"):
            record.protocol_l3 = "IPv6"
            record.source_ip = ext.get("ipv6", "src", record.frame_number)
            record.destination_ip = ext.get("ipv6", "dst", record.frame_number)
            record.ip_ttl = _safe_int(ext.get("ipv6", "hlim", record.frame_number))
            proto = _safe_int(ext.get("ipv6", "nxt", record.frame_number))
            record.protocol = {6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}.get(proto, str(proto) if proto is not None else None)
        elif hasattr(ext.packet, "arp"):
            record.protocol_l3 = "ARP"
            record.arp_opcode = _safe_int(ext.get("arp", "opcode", record.frame_number))
            record.arp_sender_mac = ext.get("arp", "src_hw_mac", record.frame_number)
            record.arp_sender_ip = ext.get("arp", "src_proto_ipv4", record.frame_number)
            record.arp_target_mac = ext.get("arp", "dst_hw_mac", record.frame_number)
            record.arp_target_ip = ext.get("arp", "dst_proto_ipv4", record.frame_number)


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

from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Generator, Optional, TYPE_CHECKING
import ipaddress

from pcap_tool.logging import get_logger
from ..core.constants import (
    TLS_HANDSHAKE_TYPE_MAP,
    TLS_VERSION_MAP,
    TLS_ALERT_LEVEL_MAP,
    TLS_ALERT_DESCRIPTION_MAP,
    DNS_QUERY_TYPE_MAP,
    DNS_RCODE_MAP,
    DHCP_MESSAGE_TYPE_MAP,
    ZSCALER_EXAMPLE_IP_RANGES,
    ZPA_SYNTHETIC_IP_RANGE,
)
from ..models import PcapRecord
from functools import wraps
from .base import BaseParser
from .utils import _safe_int, _safe_str_to_bool

logger = get_logger(__name__)

USE_PYSHARK = False
try:  # pragma: no cover - import check
    import pyshark  # type: ignore
    USE_PYSHARK = True
except Exception:  # pragma: no cover - import check
    pass

if TYPE_CHECKING:  # pragma: no cover - hint for static analyzers
    from pyshark.packet.packet import Packet as PySharkPacket

_TCP_FLOW_HISTORY: dict[tuple[str, int, str, int], deque] = defaultdict(deque)
_TCP_FLOW_HISTORY_MAX = 64


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


def _check_ip_in_ranges(ip_str: Optional[str], ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    if not ip_str:
        return False
    try:
        ip_addr = ipaddress.ip_address(ip_str)
        for net_range in ranges:
            if ip_addr in net_range:
                return True
    except ValueError:
        logger.debug(f"Invalid IP address string for range check: {ip_str}")
        return False
    return False


def _flow_history_key(src_ip: Optional[str], src_port: Optional[int], dst_ip: Optional[str], dst_port: Optional[int]) -> tuple[str, int, str, int]:
    """Create a normalized flow key for the heuristic cache."""
    return (
        src_ip or "",
        src_port or -1,
        dst_ip or "",
        dst_port or -1,
    )


def _update_flow_history(key: tuple[str, int, str, int], seq: Optional[int], ack: Optional[int], win: Optional[int], length: int) -> None:
    """Store packet values for a flow, trimming old history."""
    hist = _TCP_FLOW_HISTORY[key]
    hist.append({"seq": seq, "ack": ack, "win": win, "len": length})
    if len(hist) > _TCP_FLOW_HISTORY_MAX:
        hist.popleft()


def _heuristic_tcp_flags(key: tuple[str, int, str, int], seq: Optional[int], ack: Optional[int], win: Optional[int], length: int) -> dict[str, bool]:
    """Infer basic TCP analysis flags without TShark's analysis layer."""
    hist = _TCP_FLOW_HISTORY[key]
    seqs = {h["seq"] for h in hist if h.get("seq") is not None}

    flags = {
        "retransmission": False,
        "duplicate_ack": False,
        "out_of_order": False,
        "zero_window": False,
    }

    if seq is not None and seq in seqs:
        flags["retransmission"] = True

    if hist:
        last = hist[-1]
        if ack is not None and ack == last.get("ack") and length == 0:
            flags["duplicate_ack"] = True
        if seq is not None:
            expected = (last.get("seq") or 0) + (last.get("len") or 0)
            if seq < expected and seq not in seqs:
                flags["out_of_order"] = True
        if win == 0 and last.get("win") not in (None, 0):
            flags["zero_window"] = True

    _update_flow_history(key, seq, ack, win, length)
    return flags


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


def handle_parse_errors(func):
    """Decorator to log and re-raise errors during parsing."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            yield from func(*args, **kwargs)
        except pyshark.capture.capture.TSharkCrashException as exc:  # pragma: no cover - runtime protection
            logger.error("TShark crashed: %s", exc)
            raise RuntimeError("TShark crashed during parsing") from exc
        except Exception as exc:  # pragma: no cover - runtime protection
            logger.error("Error parsing pcap: %s", exc, exc_info=True)
            raise

    return wrapper


class PySharkParser(BaseParser):
    """Parser implementation using :mod:`pyshark` with helper methods."""

    def __init__(self, *, load_timeout: int = 5) -> None:
        """Initialize the parser.

        ``load_timeout`` sets the default timeout (in seconds) used when
        loading packets via :mod:`pyshark`.
        """

        self.load_timeout = load_timeout
        self.flow_orientation: dict[Any, tuple[str | None, int | None]] = {}
        self.tcp_syn_times: dict[tuple[str, int, str, int, str], float] = {}
        self.tcp_rtt_samples: defaultdict[tuple[str, int, str, int, str], list[float]] = defaultdict(list)

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
        self._extract_tcp_data(extractor, record)
        self._extract_tls_data(extractor, record)
        self._extract_dns_data(extractor, record)
        self._extract_http_data(extractor, record)
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

    def _extract_tcp_data(self, ext: PacketExtractor, record: PcapRecord) -> None:
        """Populate TCP-related fields on ``record``."""

        if record.protocol != "TCP" or not hasattr(ext.packet, "tcp"):
            if record.protocol == "UDP" and record.destination_port is None:
                record.source_port = _safe_int(ext.get("udp", "srcport", record.frame_number))
                record.destination_port = _safe_int(ext.get("udp", "dstport", record.frame_number))
                if record.destination_port == 443:
                    record.is_quic = bool(hasattr(ext.packet, "quic"))
            return

        record.source_port = _safe_int(ext.get("tcp", "srcport", record.frame_number))
        record.destination_port = _safe_int(ext.get("tcp", "dstport", record.frame_number))
        record.tcp_flags_syn = ext.get("tcp", "flags_syn", record.frame_number, is_flag=True)
        record.tcp_flags_ack = ext.get("tcp", "flags_ack", record.frame_number, is_flag=True)
        record.tcp_flags_fin = ext.get("tcp", "flags_fin", record.frame_number, is_flag=True)
        record.tcp_flags_rst = ext.get("tcp", "flags_rst", record.frame_number, is_flag=True)
        record.tcp_flags_psh = ext.get("tcp", "flags_push", record.frame_number, is_flag=True)
        record.tcp_flags_urg = ext.get("tcp", "flags_urg", record.frame_number, is_flag=True)
        record.tcp_sequence_number = _safe_int(ext.get("tcp", "seq", record.frame_number))
        record.tcp_acknowledgment_number = _safe_int(ext.get("tcp", "ack", record.frame_number))
        record.tcp_window_size = _safe_int(ext.get("tcp", "window_size_value", record.frame_number))
        record.tcp_stream_index = _safe_int(ext.get("tcp", "stream", record.frame_number))

        flow_key = (record.source_ip, record.source_port, record.destination_ip, record.destination_port)
        orient_key = record.tcp_stream_index or flow_key
        orient = self.flow_orientation.get(orient_key)
        if orient is None and record.tcp_flags_syn and not record.tcp_flags_ack:
            orient = (record.source_ip, record.source_port)
            self.flow_orientation[orient_key] = orient
        if orient is not None:
            record.is_src_client = record.source_ip == orient[0] and record.source_port == orient[1]

        if record.tcp_flags_syn and not record.tcp_flags_ack:
            rtt_key = (
                record.source_ip or "",
                record.source_port or -1,
                record.destination_ip or "",
                record.destination_port or -1,
                "TCP",
            )
            if record.source_ip and record.destination_ip and record.source_port is not None and record.destination_port is not None:
                self.tcp_syn_times[rtt_key] = record.timestamp
            else:
                logger.warning(
                    "Could not extract SYN data for RTT calculation for packet %s in flow %s",
                    record.frame_number,
                    rtt_key,
                )
        elif record.tcp_flags_syn and record.tcp_flags_ack:
            rtt_key_rev = (
                record.destination_ip or "",
                record.destination_port or -1,
                record.source_ip or "",
                record.source_port or -1,
                "TCP",
            )
            syn_ts = self.tcp_syn_times.pop(rtt_key_rev, None)
            if syn_ts is not None:
                record.tcp_rtt_ms = (record.timestamp - syn_ts) * 1000.0
                self.tcp_rtt_samples[rtt_key_rev].append(record.tcp_rtt_ms)
            else:
                logger.debug(
                    "No matching SYN found for SYN-ACK packet %s in flow %s",
                    record.frame_number,
                    rtt_key_rev,
                )

        # --- TCP analysis flags and heuristics ---
        analysis_layer = getattr(ext.packet.tcp, "analysis", None)

        def _get_analysis_attr(attr: str) -> Any:
            if analysis_layer and hasattr(analysis_layer, attr):
                return getattr(analysis_layer, attr)
            return getattr(ext.packet.tcp, f"analysis_{attr}", None)

        adv_window_val = record.tcp_window_size or _safe_int(ext.get("tcp", "window_size", record.frame_number))
        payload_len_int = _safe_int(ext.get("tcp", "len", record.frame_number)) or 0

        if _get_analysis_attr("retransmission") is not None:
            record.tcp_analysis_retransmission_flags.append("retransmission")
        if _get_analysis_attr("fast_retransmission") is not None:
            record.tcp_analysis_retransmission_flags.append("fast_retransmission")
            if record.dup_ack_num is None:
                record.dup_ack_num = 3
        if _get_analysis_attr("spurious_retransmission") is not None:
            record.tcp_analysis_retransmission_flags.append("spurious_retransmission")

        if _get_analysis_attr("duplicate_ack") is not None:
            record.tcp_analysis_duplicate_ack_flags.append("duplicate_ack")
        dup_num_raw = _get_analysis_attr("duplicate_ack_num")
        if dup_num_raw is not None:
            val = _safe_int(dup_num_raw)
            if val is not None:
                record.dup_ack_num = val
                record.tcp_analysis_duplicate_ack_flags.append(f"duplicate_ack_num:{val}")
            else:
                record.tcp_analysis_duplicate_ack_flags.append("duplicate_ack_num")

        if _get_analysis_attr("out_of_order") is not None:
            record.tcp_analysis_out_of_order_flags.append("out_of_order")
        if _get_analysis_attr("lost_segment") is not None:
            record.tcp_analysis_out_of_order_flags.append("lost_segment")

        if _get_analysis_attr("zero_window") is not None:
            record.tcp_analysis_window_flags.append("zero_window")
        if _get_analysis_attr("zero_window_probe") is not None:
            if "zero_window" not in record.tcp_analysis_window_flags:
                record.tcp_analysis_window_flags.append("zero_window")
            record.tcp_analysis_window_flags.append("zero_window_probe")
        if _get_analysis_attr("zero_window_probe_ack") is not None:
            if "zero_window" not in record.tcp_analysis_window_flags:
                record.tcp_analysis_window_flags.append("zero_window")
            record.tcp_analysis_window_flags.append("zero_window_probe_ack")
        if _get_analysis_attr("window_update") is not None:
            record.tcp_analysis_window_flags.append("window_update")

        if not analysis_layer:
            h_flags = _heuristic_tcp_flags(
                flow_key,
                record.tcp_sequence_number,
                record.tcp_acknowledgment_number,
                adv_window_val,
                payload_len_int,
            )
            if h_flags["retransmission"]:
                record.tcp_analysis_retransmission_flags.append("heuristic_retransmission")
            if h_flags["duplicate_ack"]:
                record.tcp_analysis_duplicate_ack_flags.append("heuristic_duplicate_ack")
            if h_flags["out_of_order"]:
                record.tcp_analysis_out_of_order_flags.append("heuristic_out_of_order")
            if h_flags["zero_window"]:
                record.tcp_analysis_window_flags.append("heuristic_zero_window")

        record.adv_window = adv_window_val

    def _extract_tls_data(self, ext: PacketExtractor, record: PcapRecord) -> None:
        """Extract TLS-related metadata."""

        if not hasattr(ext.packet, "tls"):
            return

        record.sni = _extract_sni_pyshark(ext.packet)
        record.tls_record_version = TLS_VERSION_MAP.get(
            _safe_int(ext.get("tls", "record_version", record.frame_number)),
            ext.get("tls", "record_version", record.frame_number),
        )

        hs_type = ext.get("tls", "handshake_type", record.frame_number)
        if hs_type is not None:
            record.tls_handshake_type = TLS_HANDSHAKE_TYPE_MAP.get(_safe_int(hs_type), str(hs_type))

        hs_ver = ext.get("tls", "handshake_version", record.frame_number)
        if hs_ver is not None:
            record.tls_handshake_version = TLS_VERSION_MAP.get(_safe_int(hs_ver), str(hs_ver))

        record.tls_effective_version = record.tls_handshake_version or record.tls_record_version

        if ext.get("tls", "record_content_type", record.frame_number) == "21":
            alert_level = ext.get("tls", "alert_message_level", record.frame_number)
            alert_desc = ext.get("tls", "alert_message_desc", record.frame_number)
            if alert_level is not None:
                record.tls_alert_level = TLS_ALERT_LEVEL_MAP.get(_safe_int(alert_level), str(alert_level))
            if alert_desc is not None:
                record.tls_alert_message_description = TLS_ALERT_DESCRIPTION_MAP.get(
                    _safe_int(alert_desc), str(alert_desc)
                )

    def _extract_dns_data(self, ext: PacketExtractor, record: PcapRecord) -> None:
        """Extract DNS fields."""

        if not hasattr(ext.packet, "dns"):
            return

        record.dns_query_name = ext.get("dns", "qry_name", record.frame_number)
        qry_type = ext.get("dns", "qry_type", record.frame_number)
        if qry_type is not None:
            record.dns_query_type = DNS_QUERY_TYPE_MAP.get(_safe_int(qry_type), str(qry_type))

        if ext.get("dns", "flags_response", record.frame_number, is_flag=True):
            rcode = ext.get("dns", "flags_rcode", record.frame_number)
            if rcode is not None:
                record.dns_response_code = DNS_RCODE_MAP.get(_safe_int(rcode), str(rcode))

            addrs = []
            for field in ["a", "aaaa"]:
                if hasattr(ext.packet.dns, field):
                    val = getattr(ext.packet.dns, field)
                    if isinstance(val, list):
                        addrs.extend(str(v.show) if hasattr(v, "show") else str(v) for v in val)
                    elif isinstance(val, str):
                        addrs.extend([a.strip() for a in val.split(",") if a.strip()])
                    else:
                        addrs.append(str(val.show) if hasattr(val, "show") else str(val))
            if addrs:
                record.dns_response_addresses = addrs

            if hasattr(ext.packet.dns, "cname"):
                cname_val = getattr(ext.packet.dns, "cname")
                record.dns_response_cname_target = (
                    str(cname_val[0].show) if isinstance(cname_val, list) else str(cname_val.show)
                ) if hasattr(cname_val, "show") else str(cname_val)

    def _extract_http_data(self, ext: PacketExtractor, record: PcapRecord) -> None:
        """Extract HTTP request/response fields."""

        if not hasattr(ext.packet, "http"):
            return

        if hasattr(ext.packet.http, "request_method"):
            record.http_request_method = ext.get("http", "request_method", record.frame_number)
            record.http_request_uri = ext.get("http", "request_uri", record.frame_number)
            record.http_request_host_header = ext.get("http", "host", record.frame_number)
            record.http_x_forwarded_for_header = ext.get("http", "x_forwarded_for", record.frame_number)
        else:
            code = ext.get("http", "response_code", record.frame_number)
            if code is not None:
                record.http_response_code = _safe_int(code)
            record.http_response_location_header = ext.get("http", "location", record.frame_number)

    @handle_parse_errors
    def parse(
        self,
        file_path: str,
        max_packets: Optional[int],
        *,
        start: int = 0,
        slice_size: Optional[int] = None,
    ) -> Generator[PcapRecord, None, None]:
        """Yield :class:`PcapRecord` objects for ``file_path``."""

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


def _parse_with_pyshark(
    file_path: str,
    max_packets: Optional[int],
    *,
    start: int = 0,
    slice_size: Optional[int] = None,
) -> Generator[PcapRecord, None, None]:
    logger.info(f"Starting PCAP parsing with PyShark for: {file_path}")
    generated_records = 0
    cap = None
    flow_orientation: dict[Any, tuple[str | None, int | None]] = {}
    tcp_syn_times: dict[tuple[str, int, str, int, str], float] = {}
    tcp_rtt_samples: defaultdict[tuple[str, int, str, int, str], list[float]] = defaultdict(list)
    try:
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
            cap.load_packets(timeout=5)
            logger.info(
                f"PyShark capture loaded. Number of packets initially found by PyShark: {len(cap)}"
            )
            if len(cap) == 0:
                logger.warning(
                    f"PyShark found 0 packets in {file_path}. Check file and filters."
                )
        except Exception as e_load:
            logger.error(
                f"Error during PyShark cap.load_packets() or initial packet count: {e_load}",
                exc_info=True,
            )
    except pyshark.tshark.tshark.TSharkNotFoundException as e_tshark:
        logger.error(f"PyShark TSharkNotFoundException: {e_tshark}. Ensure TShark is installed and in PATH.")
        raise RuntimeError(f"PyShark critical error: TShark not found.") from e_tshark
    except Exception as e_init:
        logger.error(f"PyShark error opening/initializing pcap file {file_path}: {e_init}")
        raise RuntimeError(f"PyShark failed to open or initialize {file_path}.") from e_init

    def _extract_certificate_metadata(pkt) -> dict:
        """Return TLS certificate details from ``pkt`` if present."""
        if not hasattr(pkt, "tls"):
            return {}
        tls_obj = pkt.tls
        cert = getattr(tls_obj, "handshake_certificate", None)
        if cert is None:
            cert = getattr(tls_obj, "handshake__certificate", None)
        if cert is None:
            return {}
        leaf = cert[0] if isinstance(cert, list) else cert
        meta: dict[str, Any] = {}
        meta["tls_cert_subject_cn"] = getattr(leaf, "x509sat_commonName", None)
        meta["tls_cert_san_dns"] = getattr(leaf, "get_multiple_fields", lambda *_: None)("x509sat_dnsName")
        meta["tls_cert_san_ip"] = getattr(leaf, "get_multiple_fields", lambda *_: None)("x509sat_ipAddress")
        meta["tls_cert_issuer_cn"] = getattr(leaf, "x509sat_issuer_commonName", None)
        meta["tls_cert_serial_number"] = getattr(leaf, "x509af_serial_number", None)
        nb = getattr(leaf, "x509af_validity_not_before", None)
        na = getattr(leaf, "x509af_validity_not_after", None)
        if nb:
            try:
                meta["tls_cert_not_before"] = datetime.strptime(str(nb), "%Y-%m-%d %H:%M:%S")
            except Exception:
                meta["tls_cert_not_before"] = None
        if na:
            try:
                meta["tls_cert_not_after"] = datetime.strptime(str(na), "%Y-%m-%d %H:%M:%S")
            except Exception:
                meta["tls_cert_not_after"] = None
        meta["tls_cert_sig_alg"] = getattr(leaf, "x509af_signature_algo", None)
        key_len = getattr(leaf, "x509af_public_key_length", None)
        if key_len is not None:
            meta["tls_cert_key_length"] = _safe_int(key_len)
        subj_cn = meta.get("tls_cert_subject_cn")
        issuer_cn = meta.get("tls_cert_issuer_cn")
        if subj_cn is not None and issuer_cn is not None:
            meta["tls_cert_is_self_signed"] = subj_cn == issuer_cn
        return meta

    packet_count = 0
    try:
        for packet in cap:
            if max_packets is not None and generated_records >= max_packets:
                logger.info(f"PyShark: Reached max_packets limit of {max_packets}.")
                break
            packet_count += 1
            try:
                timestamp = float(packet.sniff_timestamp)
                frame_number = _safe_int(packet.number) or 0

                source_ip, destination_ip, source_port, destination_port, protocol_l4, sni = None, None, None, None, None, None
                source_mac, destination_mac, protocol_l3, packet_length_val = None, None, None, None
                ip_ttl, ip_flags_df_bool, ip_id_val, dscp_val = None, None, None, None # Renamed ip_flags_df to ip_flags_df_bool
                tcp_flags_syn, tcp_flags_ack, tcp_flags_fin, tcp_flags_rst = None, None, None, None
                tcp_flags_psh, tcp_flags_urg, tcp_flags_ece, tcp_flags_cwr = None, None, None, None
                tcp_sequence_number, tcp_acknowledgment_number, tcp_window_size = None, None, None
                tcp_options_mss, tcp_options_sack_permitted, tcp_options_window_scale = None, None, None
                tcp_stream_index = None
                is_src_client_val = None
                tcp_analysis_retransmission_flags = []
                tcp_analysis_duplicate_ack_flags = []
                tcp_analysis_out_of_order_flags = []
                tcp_analysis_window_flags = []
                dup_ack_num_val, adv_window_val = None, None
                tls_handshake_type_str, tls_handshake_version_str, tls_record_version_str = None, None, None
                tls_cipher_suites_offered_list, tls_cipher_suite_selected_str = None, None
                tls_alert_description_str, tls_alert_level_str = None, None
                tls_effective_version_str = None
                dns_query_name_str, dns_query_type_str, dns_response_code_str = None, None, None
                dns_response_addresses_list, dns_response_cname_target_str = None, None
                http_request_method_str, http_request_uri_str, http_request_host_header_str = None, None, None
                http_response_code_int, http_response_location_header_str, http_x_forwarded_for_header_str = None, None, None
                icmp_type_val, icmp_code_val, icmp_frag_mtu_val = None, None, None
                arp_opcode_val, arp_sender_mac_str, arp_sender_ip_str = None, None, None
                arp_target_mac_str, arp_target_ip_str = None, None
                dhcp_message_type_str = None
                gre_protocol_str, esp_spi_str = None, None
                quic_initial_packet = None
                is_quic_flag = None
                is_zscaler_ip_flag, is_zpa_synthetic_ip_flag = None, None # Will become False if IPs exist and don't match
                ssl_inspection_active_flag = None
                zscaler_policy_block_type_str = None

                raw_summary = str(packet.highest_layer) if hasattr(packet, 'highest_layer') else 'N/A'
                if hasattr(packet, 'length'):
                    packet_length_val = _safe_int(packet.length)

                if hasattr(packet, 'eth'):
                    eth_layer = packet.eth
                    source_mac = _get_pyshark_layer_attribute(eth_layer, 'src', frame_number)
                    destination_mac = _get_pyshark_layer_attribute(eth_layer, 'dst', frame_number)

                ip_layer_obj = None
                if hasattr(packet, 'ip'):
                    protocol_l3 = "IPv4"; ip_layer_obj = packet.ip
                    proto_num_str = _get_pyshark_layer_attribute(ip_layer_obj, 'proto', frame_number)
                    if proto_num_str is not None:
                        protocol_num = _safe_int(proto_num_str)
                        if protocol_num == 1: protocol_l4 = "ICMP"
                        elif protocol_num == 6: protocol_l4 = "TCP"
                        elif protocol_num == 17: protocol_l4 = "UDP"
                        elif protocol_num == 47: protocol_l4 = "GRE"
                        elif protocol_num == 50: protocol_l4 = "ESP"
                        else: protocol_l4 = str(protocol_num)
                    source_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'src', frame_number)
                    destination_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'dst', frame_number)
                    ttl_str = _get_pyshark_layer_attribute(ip_layer_obj, 'ttl', frame_number)
                    if ttl_str:
                        ip_ttl = _safe_int(ttl_str)
                    ip_flags_df_bool = _get_pyshark_layer_attribute(ip_layer_obj, 'flags_df', frame_number, is_flag=True)
                    ip_id_val = _get_pyshark_layer_attribute(ip_layer_obj, 'id', frame_number)
                    dscp_str = _get_pyshark_layer_attribute(ip_layer_obj, 'dsfield_dscp', frame_number)
                    if dscp_str:
                        dscp_val = _safe_int(dscp_str)

                elif hasattr(packet, 'ipv6'):
                    protocol_l3 = "IPv6"; ip_layer_obj = packet.ipv6
                    proto_num_str = _get_pyshark_layer_attribute(ip_layer_obj, 'nxt', frame_number)
                    if proto_num_str is not None:
                        protocol_num = _safe_int(proto_num_str)
                        if protocol_num == 6: protocol_l4 = "TCP"
                        elif protocol_num == 17: protocol_l4 = "UDP"
                        elif protocol_num == 58: protocol_l4 = "ICMPv6"
                        elif protocol_num == 47: protocol_l4 = "GRE"
                        elif protocol_num == 50: protocol_l4 = "ESP"
                        else: protocol_l4 = str(protocol_num)
                    source_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'src', frame_number)
                    destination_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'dst', frame_number)
                    hlim_str = _get_pyshark_layer_attribute(ip_layer_obj, 'hlim', frame_number)
                    if hlim_str:
                        ip_ttl = _safe_int(hlim_str)
                    # IPv6 doesn't have a direct DF flag like IPv4. Fragmentation is handled by extension headers.
                    # DSCP from tclass
                    tclass_dscp_str = _get_pyshark_layer_attribute(ip_layer_obj, 'tclass_dscp', frame_number)
                    if tclass_dscp_str:
                        dscp_val = _safe_int(tclass_dscp_str)
                    elif hasattr(ip_layer_obj, 'tclass'):
                        tclass_hex = _get_pyshark_layer_attribute(ip_layer_obj, 'tclass', frame_number)
                        if tclass_hex:
                            try: dscp_val = int(str(tclass_hex), 16) >> 2
                            except ValueError: logger.warning(f"Frame {frame_number}: Could not parse IPv6 tclass '{tclass_hex}' for DSCP.")

                elif hasattr(packet, 'arp'):
                    protocol_l3 = "ARP"
                    arp_layer = packet.arp
                    opcode_str = _get_pyshark_layer_attribute(arp_layer, 'opcode', frame_number)
                    if opcode_str:
                        arp_opcode_val = _safe_int(opcode_str)
                    arp_sender_mac_str = _get_pyshark_layer_attribute(arp_layer, 'src_hw_mac', frame_number)
                    arp_sender_ip_str = _get_pyshark_layer_attribute(arp_layer, 'src_proto_ipv4', frame_number)
                    arp_target_mac_str = _get_pyshark_layer_attribute(arp_layer, 'dst_hw_mac', frame_number)
                    arp_target_ip_str = _get_pyshark_layer_attribute(arp_layer, 'dst_proto_ipv4', frame_number)
                else:
                    # For non-IP/non-ARP, yield basic L2 info if available
                    if packet_count > generated_records:


                        yield PcapRecord(

                            frame_number=frame_number,
                            timestamp=timestamp,
                            source_mac=source_mac,
                            destination_mac=destination_mac,
                            packet_length=packet_length_val,
                            raw_packet_summary=raw_summary,
                            tcp_rtt_ms=None,

                            # Other fields default to None
                        )

                        generated_records += 1

                    continue # Skip to next packet

                transport_layer_obj = None
                tcp_rtt_ms_sample = None
                if protocol_l4 == "TCP" and hasattr(packet, 'tcp'):
                    transport_layer_obj = packet.tcp; tcp_layer = transport_layer_obj
                    tcp_flags_syn = _get_pyshark_layer_attribute(tcp_layer, 'flags_syn', frame_number, is_flag=True)
                    tcp_flags_ack = _get_pyshark_layer_attribute(tcp_layer, 'flags_ack', frame_number, is_flag=True)
                    tcp_flags_fin = _get_pyshark_layer_attribute(tcp_layer, 'flags_fin', frame_number, is_flag=True)
                    tcp_flags_rst = _get_pyshark_layer_attribute(
                        tcp_layer,
                        'flags_rst',
                        frame_number,
                        is_flag=True,
                    )
                    if tcp_flags_rst is None:
                        tcp_flags_rst = _get_pyshark_layer_attribute(
                            tcp_layer,
                            'flags_reset',
                            frame_number,
                            is_flag=True,
                        )
                    tcp_flags_psh = _get_pyshark_layer_attribute(tcp_layer, 'flags_push', frame_number, is_flag=True) # pyshark uses 'flags_push'
                    tcp_flags_urg = _get_pyshark_layer_attribute(tcp_layer, 'flags_urg', frame_number, is_flag=True)
                    tcp_flags_ece = _get_pyshark_layer_attribute(tcp_layer, 'flags_ece', frame_number, is_flag=True)
                    tcp_flags_cwr = _get_pyshark_layer_attribute(tcp_layer, 'flags_cwr', frame_number, is_flag=True)

                    seq_str = _get_pyshark_layer_attribute(tcp_layer, 'seq', frame_number)
                    if seq_str:
                        tcp_sequence_number = _safe_int(seq_str)
                    ack_str = _get_pyshark_layer_attribute(tcp_layer, 'ack', frame_number)
                    if ack_str:
                        tcp_acknowledgment_number = _safe_int(ack_str)

                    srcport_str = _get_pyshark_layer_attribute(tcp_layer, 'srcport', frame_number)
                    if srcport_str:
                        source_port = _safe_int(srcport_str)
                    dstport_str = _get_pyshark_layer_attribute(tcp_layer, 'dstport', frame_number)
                    if dstport_str:
                        destination_port = _safe_int(dstport_str)

                    win_val_str = _get_pyshark_layer_attribute(tcp_layer, 'window_size_value', frame_number)
                    if win_val_str:
                        tcp_window_size = _safe_int(win_val_str)
                        adv_window_val = _safe_int(win_val_str)
                    else: # Fallback
                        win_str = _get_pyshark_layer_attribute(tcp_layer, 'window_size', frame_number)
                        if win_str:
                            tcp_window_size = _safe_int(win_str)
                            adv_window_val = _safe_int(win_str)

                    stream_str = _get_pyshark_layer_attribute(tcp_layer, 'stream', frame_number)
                    if stream_str:
                        tcp_stream_index = _safe_int(stream_str)

                    mss_val_str = _get_pyshark_layer_attribute(tcp_layer, 'options_mss_val', frame_number)
                    if mss_val_str:
                        tcp_options_mss = _safe_int(mss_val_str)
                    else: # Fallback
                        mss_str = _get_pyshark_layer_attribute(tcp_layer, 'mss_val', frame_number)
                        if mss_str:
                            tcp_options_mss = _safe_int(mss_str)

                    sack_perm_str = _get_pyshark_layer_attribute(tcp_layer, 'options_sack_permit', frame_number) # Note: pyshark might use 'sack_perm' or 'options_sack_permit'
                    if sack_perm_str is not None: tcp_options_sack_permitted = _safe_str_to_bool(sack_perm_str)
                    else: # Fallback for older PyShark or different field name
                        sack_perm_alt_str = _get_pyshark_layer_attribute(tcp_layer, 'sack_perm', frame_number)
                        if sack_perm_alt_str is not None: tcp_options_sack_permitted = _safe_str_to_bool(sack_perm_alt_str)

                    wscale_val_str = _get_pyshark_layer_attribute(tcp_layer, 'options_wscale_val', frame_number)
                    if wscale_val_str:
                        tcp_options_window_scale = _safe_int(wscale_val_str)
                    else: # Fallback for 'window_scale_multiplier' or 'ws_val'
                        wscale_mult_str = _get_pyshark_layer_attribute(tcp_layer, 'window_scale_multiplier', frame_number)
                        if wscale_mult_str:
                            tcp_options_window_scale = _safe_int(wscale_mult_str)

                    payload_len_str = _get_pyshark_layer_attribute(tcp_layer, 'len', frame_number)
                    payload_len_int = _safe_int(payload_len_str) if payload_len_str else 0
                    flow_key = _flow_history_key(source_ip, source_port, destination_ip, destination_port)

                    orient_key = tcp_stream_index if tcp_stream_index is not None else flow_key
                    orient = flow_orientation.get(orient_key)
                    if orient is None and tcp_flags_syn and not tcp_flags_ack:
                        orient = (source_ip, source_port)
                        flow_orientation[orient_key] = orient
                    if orient is not None:
                        is_src_client_val = (
                            source_ip == orient[0] and source_port == orient[1]
                        )

                    tcp_rtt_ms_sample = None
                    if tcp_flags_syn and not tcp_flags_ack:
                        rtt_key = (
                            source_ip or "",
                            source_port or -1,
                            destination_ip or "",
                            destination_port or -1,
                            "TCP",
                        )
                        if rtt_key not in tcp_syn_times:
                            if (
                                source_ip
                                and destination_ip
                                and source_port is not None
                                and destination_port is not None
                            ):
                                tcp_syn_times[rtt_key] = timestamp
                            else:
                                logger.warning(
                                    "Could not extract SYN data for RTT calculation for packet %s in flow %s",
                                    frame_number,
                                    rtt_key,
                                )
                    elif tcp_flags_syn and tcp_flags_ack:
                        rtt_key_rev = (
                            destination_ip or "",
                            destination_port or -1,
                            source_ip or "",
                            source_port or -1,
                            "TCP",
                        )
                        syn_ts = tcp_syn_times.get(rtt_key_rev)
                        if syn_ts is not None:
                            tcp_rtt_ms_sample = (timestamp - syn_ts) * 1000.0
                            tcp_rtt_samples[rtt_key_rev].append(tcp_rtt_ms_sample)
                            del tcp_syn_times[rtt_key_rev]
                        else:
                            logger.debug(
                                "No matching SYN found for SYN-ACK packet %s in flow %s",
                                frame_number,
                                rtt_key_rev,
                            )

                    if tcp_layer:
                        analysis_layer = getattr(tcp_layer, 'analysis', None)

                        def _get_analysis_attr(attr: str) -> Any:
                            if analysis_layer and hasattr(analysis_layer, attr):
                                return getattr(analysis_layer, attr)
                            return getattr(tcp_layer, f'analysis_{attr}', None)

                        if _get_analysis_attr('retransmission') is not None:
                            tcp_analysis_retransmission_flags.append('retransmission')
                        if _get_analysis_attr('fast_retransmission') is not None:
                            tcp_analysis_retransmission_flags.append('fast_retransmission')
                            if dup_ack_num_val is None:
                                dup_ack_num_val = 3
                        if _get_analysis_attr('spurious_retransmission') is not None:
                            tcp_analysis_retransmission_flags.append('spurious_retransmission')

                        if _get_analysis_attr('duplicate_ack') is not None:
                            tcp_analysis_duplicate_ack_flags.append('duplicate_ack')
                        dup_num_raw = _get_analysis_attr('duplicate_ack_num')
                        if dup_num_raw is not None:
                            try:
                                dup_ack_num_val = _safe_int(dup_num_raw)
                                if dup_ack_num_val is not None:
                                    tcp_analysis_duplicate_ack_flags.append(f'duplicate_ack_num:{dup_ack_num_val}')
                                else:
                                    tcp_analysis_duplicate_ack_flags.append('duplicate_ack_num')
                            except Exception:
                                tcp_analysis_duplicate_ack_flags.append('duplicate_ack_num')

                        if _get_analysis_attr('out_of_order') is not None:
                            tcp_analysis_out_of_order_flags.append('out_of_order')
                        if _get_analysis_attr('lost_segment') is not None:
                            tcp_analysis_out_of_order_flags.append('lost_segment')

                        if _get_analysis_attr('zero_window') is not None:
                            tcp_analysis_window_flags.append('zero_window')
                        if _get_analysis_attr('zero_window_probe') is not None:
                            if 'zero_window' not in tcp_analysis_window_flags:
                                tcp_analysis_window_flags.append('zero_window')
                            tcp_analysis_window_flags.append('zero_window_probe')
                        if _get_analysis_attr('zero_window_probe_ack') is not None:
                            if 'zero_window' not in tcp_analysis_window_flags:
                                tcp_analysis_window_flags.append('zero_window')
                            tcp_analysis_window_flags.append('zero_window_probe_ack')
                        if _get_analysis_attr('window_update') is not None:
                            tcp_analysis_window_flags.append('window_update')

                        _update_flow_history(
                            flow_key,
                            tcp_sequence_number,
                            tcp_acknowledgment_number,
                            adv_window_val,
                            payload_len_int,
                        )
                    else:
                        h_flags = _heuristic_tcp_flags(
                            flow_key,
                            tcp_sequence_number,
                            tcp_acknowledgment_number,
                            adv_window_val,
                            payload_len_int,
                        )
                        if h_flags['retransmission']:
                            tcp_analysis_retransmission_flags.append('heuristic_retransmission')
                        if h_flags['duplicate_ack']:
                            tcp_analysis_duplicate_ack_flags.append('heuristic_duplicate_ack')
                        if h_flags['out_of_order']:
                            tcp_analysis_out_of_order_flags.append('heuristic_out_of_order')
                        if h_flags['zero_window']:
                            tcp_analysis_window_flags.append('heuristic_zero_window')

                elif protocol_l4 == "UDP" and hasattr(packet, 'udp'):
                    transport_layer_obj = packet.udp

                if transport_layer_obj:
                    srcport_str = _get_pyshark_layer_attribute(transport_layer_obj, 'srcport', frame_number)
                    if srcport_str:
                        source_port = _safe_int(srcport_str)
                    dstport_str = _get_pyshark_layer_attribute(transport_layer_obj, 'dstport', frame_number)
                    if dstport_str:
                        destination_port = _safe_int(dstport_str)

                if protocol_l4 == "UDP" and destination_port == 443:
                    if hasattr(packet, 'quic'):
                        is_quic_flag = True
                        logger.debug(f"Frame {frame_number}: UDP/443 with QUIC layer detected")
                    else:
                        is_quic_flag = False
                        logger.debug(f"Frame {frame_number}: UDP/443 with no QUIC fields")

                if hasattr(packet, 'tls'):
                    sni = _extract_sni_pyshark(packet)  # SNI extraction uses its own logic
                    tls_layer = packet.tls
                    raw_rec_ver = _get_pyshark_layer_attribute(tls_layer, 'record_version', frame_number)
                    if raw_rec_ver:
                        tls_record_version_str = TLS_VERSION_MAP.get(
                            _safe_int(raw_rec_ver), str(raw_rec_ver)
                        )

                    hs_type_val = _get_pyshark_layer_attribute(tls_layer, 'handshake_type', frame_number)
                    if hs_type_val is not None:
                        tls_handshake_type_str = TLS_HANDSHAKE_TYPE_MAP.get(
                            _safe_int(hs_type_val), str(hs_type_val)
                        )

                    hs_ver_val = _get_pyshark_layer_attribute(tls_layer, 'handshake_version', frame_number)
                    if hs_ver_val is not None:
                        tls_handshake_version_str = TLS_VERSION_MAP.get(
                            _safe_int(hs_ver_val), str(hs_ver_val)
                        )

                    # Supported or selected version fields vary across tshark versions
                    supp_ver_val = None
                    for attr in (
                        'handshake_extensions_supported_version',
                        'handshake_supported_version',
                        'handshake_supported_versions',
                    ):
                        if hasattr(tls_layer, attr):
                            supp_ver_val = getattr(tls_layer, attr)
                            break
                    if supp_ver_val is not None:
                        if isinstance(supp_ver_val, list):
                            ver_token = supp_ver_val[0] if supp_ver_val else None
                        else:
                            ver_token = supp_ver_val
                        if ver_token is not None:
                            tls_handshake_version_str = TLS_VERSION_MAP.get(
                                _safe_int(ver_token), str(ver_token)
                            )

                    if tls_handshake_type_str == "ClientHello" and hasattr(tls_layer, 'handshake_ciphersuites'):
                        raw_suites = getattr(tls_layer, 'handshake_ciphersuites')
                        if isinstance(raw_suites, str):
                            tls_cipher_suites_offered_list = [s.strip() for s in raw_suites.split(',')]
                        elif isinstance(raw_suites, list):
                            tls_cipher_suites_offered_list = [str(s.show) for s in raw_suites]
                        else:
                            tls_cipher_suites_offered_list = [str(raw_suites)]

                    if tls_handshake_type_str == "ServerHello" and hasattr(tls_layer, 'handshake_ciphersuite'):
                        raw_cs = getattr(tls_layer, 'handshake_ciphersuite')
                        tls_cipher_suite_selected_str = str(raw_cs.show) if hasattr(raw_cs, 'show') else str(raw_cs)

                    if tls_handshake_version_str or tls_record_version_str:
                        tls_effective_version_str = tls_handshake_version_str or tls_record_version_str
                    else:
                        logger.warning(
                            "Could not extract TLS version from packet %s", frame_number
                        )


                    if hasattr(tls_layer, 'record_content_type') and str(_get_pyshark_layer_attribute(tls_layer, 'record_content_type', frame_number)) == '21': # Alert
                        alert_level_val = _get_pyshark_layer_attribute(tls_layer, 'alert_message_level', frame_number)
                        if alert_level_val:
                            tls_alert_level_str = TLS_ALERT_LEVEL_MAP.get(
                                _safe_int(alert_level_val), str(alert_level_val)
                            )

                        # Try 'alert_message_description' first as it's more direct from newer tshark
                        alert_desc_val = _get_pyshark_layer_attribute(tls_layer, 'alert_message_description', frame_number)
                        if alert_desc_val:
                            tls_alert_description_str = TLS_ALERT_DESCRIPTION_MAP.get(
                                _safe_int(alert_desc_val), str(alert_desc_val)
                            )
                        else:  # Fallback to 'alert_message' if description not found
                            alert_msg_val = _get_pyshark_layer_attribute(tls_layer, 'alert_message', frame_number)
                            if alert_msg_val:
                                tls_alert_description_str = TLS_ALERT_DESCRIPTION_MAP.get(
                                    _safe_int(alert_msg_val), str(alert_msg_val)
                                )  # Use same map
                            else:
                                tls_alert_description_str = "Unknown Alert"



                if hasattr(packet, 'dns'):
                    dns_layer = packet.dns
                    dns_query_name_str = _get_pyshark_layer_attribute(dns_layer, 'qry_name', frame_number)
                    qry_type_val = _get_pyshark_layer_attribute(dns_layer, 'qry_type', frame_number)
                    if qry_type_val:
                        dns_query_type_str = DNS_QUERY_TYPE_MAP.get(
                            _safe_int(qry_type_val), str(qry_type_val)
                        )

                    if _get_pyshark_layer_attribute(dns_layer, 'flags_response', frame_number, is_flag=True): # Check if it's a response
                        rcode_val = _get_pyshark_layer_attribute(dns_layer, 'flags_rcode', frame_number)
                        if rcode_val:
                            dns_response_code_str = DNS_RCODE_MAP.get(
                                _safe_int(rcode_val), str(rcode_val)
                            )

                        current_response_addrs = []
                        # Handling for 'a' and 'aaaa' which can be single or list of Field objects
                        for addr_type_attr in ['a', 'aaaa']:
                            if hasattr(dns_layer, addr_type_attr):
                                val_addr_field = getattr(dns_layer, addr_type_attr)
                                if isinstance(val_addr_field, list): # List of Field objects
                                    for item_addr in val_addr_field:
                                        current_response_addrs.append(str(item_addr.show) if hasattr(item_addr, 'show') else str(item_addr))
                                elif isinstance(val_addr_field, str): # Comma-separated string
                                     current_response_addrs.extend([addr.strip() for addr in val_addr_field.split(',') if addr.strip()])
                                else: # Single Field object or simple string
                                    current_response_addrs.append(str(val_addr_field.show) if hasattr(val_addr_field, 'show') else str(val_addr_field))
                        if current_response_addrs: dns_response_addresses_list = current_response_addrs

                        if hasattr(dns_layer, 'cname'):
                            val_cname_field = getattr(dns_layer, 'cname')
                            if isinstance(val_cname_field, list) and val_cname_field: # Take the first if it's a list
                                dns_response_cname_target_str = str(val_cname_field[0].show) if hasattr(val_cname_field[0], 'show') else str(val_cname_field[0])
                            else: # Single Field object or simple string
                                dns_response_cname_target_str = str(val_cname_field.show) if hasattr(val_cname_field, 'show') else str(val_cname_field)


                if hasattr(packet, 'http'):
                    http_layer = packet.http
                    if hasattr(http_layer, 'request_method'):
                        http_request_method_str = _get_pyshark_layer_attribute(http_layer, 'request_method', frame_number)
                        http_request_uri_str = _get_pyshark_layer_attribute(http_layer, 'request_uri', frame_number)
                        http_request_host_header_str = _get_pyshark_layer_attribute(http_layer, 'host', frame_number)
                        http_x_forwarded_for_header_str = _get_pyshark_layer_attribute(http_layer, 'x_forwarded_for', frame_number)
                    elif hasattr(http_layer, 'response_code'):
                        resp_code_str = _get_pyshark_layer_attribute(http_layer, 'response_code', frame_number)
                        if resp_code_str:
                            http_response_code_int = _safe_int(resp_code_str)
                        http_response_location_header_str = _get_pyshark_layer_attribute(http_layer, 'location', frame_number)
                    # If x_forwarded_for exists but not in request (e.g. response context, though less common)
                    elif hasattr(http_layer, 'x_forwarded_for') and not http_request_method_str:
                         http_x_forwarded_for_header_str = _get_pyshark_layer_attribute(http_layer, 'x_forwarded_for', frame_number)


                icmp_layer_to_process = None
                if protocol_l4 == "ICMP" and hasattr(packet, 'icmp'):
                    icmp_layer_to_process = packet.icmp
                elif protocol_l4 == "ICMPv6" and hasattr(packet, 'icmpv6'):
                    icmp_layer_to_process = packet.icmpv6

                if icmp_layer_to_process:
                    type_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'type', frame_number)
                    if type_str:
                        icmp_type_val = _safe_int(type_str)
                    code_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'code', frame_number)
                    if code_str:
                        icmp_code_val = _safe_int(code_str)

                    # ICMP Fragmentation Needed / Packet Too Big
                    is_frag_needed_v4 = (protocol_l4 == "ICMP" and icmp_type_val == 3 and icmp_code_val == 4)
                    is_packet_too_big_v6 = (protocol_l4 == "ICMPv6" and icmp_type_val == 2 and icmp_code_val == 0)

                    if is_frag_needed_v4 or is_packet_too_big_v6:
                        mtu_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'mtu', frame_number) # Common field name
                        if mtu_str:
                            icmp_frag_mtu_val = _safe_int(mtu_str)
                        elif is_frag_needed_v4: # Fallback for ICMPv4 specific field name
                            nexthopmtu_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'nexthopmtu', frame_number)
                            if nexthopmtu_str:
                                icmp_frag_mtu_val = _safe_int(nexthopmtu_str)

                # DHCP can be over 'bootp' layer in pyshark
                dhcp_layer_source = None
                if hasattr(packet, 'dhcp'):
                    dhcp_layer_source = packet.dhcp
                elif hasattr(packet, 'bootp') and hasattr(packet.bootp, 'option_dhcp_message_type'): # Check if bootp layer has DHCP options
                    dhcp_layer_source = packet.bootp

                if dhcp_layer_source:
                    msg_type_val = _get_pyshark_layer_attribute(dhcp_layer_source, 'option_dhcp_message_type', frame_number)
                    if msg_type_val:
                        dhcp_message_type_str = DHCP_MESSAGE_TYPE_MAP.get(
                            _safe_int(msg_type_val), str(msg_type_val)
                        )


                if protocol_l4 == "GRE" and hasattr(packet, 'gre'):
                    gre_layer = packet.gre
                    gre_protocol_str = _get_pyshark_layer_attribute(gre_layer, 'proto', frame_number)

                if protocol_l4 == "ESP" and hasattr(packet, 'esp'):
                    esp_layer = packet.esp
                    esp_spi_str = _get_pyshark_layer_attribute(esp_layer, 'spi', frame_number)

                if hasattr(packet, 'quic'):
                    quic_layer = packet.quic
                    quic_log_fields = []
                    if hasattr(quic_layer, 'version'):
                        quic_log_fields.append(f"version={getattr(quic_layer, 'version')}")
                        # Check for long header type '0' (Initial)
                        long_packet_type = _get_pyshark_layer_attribute(quic_layer, 'long_packet_type', frame_number)
                        if long_packet_type is not None:
                            quic_log_fields.append(f"long_packet_type={long_packet_type}")
                            if str(long_packet_type) == '0':
                                quic_initial_packet = True
                        # Fallback: Check header_form '1' (Long header) if long_packet_type not definitive
                        elif _get_pyshark_layer_attribute(quic_layer, 'header_form', frame_number, is_flag=True): # '1' is Long Header
                            quic_initial_packet = True # Simplified, could be other long header types
                            quic_log_fields.append('header_form=1')
                        else:
                            quic_initial_packet = False # It's QUIC, has version, but not clearly Initial or Long Header
                    if quic_log_fields:
                        logger.debug(f"Frame {frame_number}: QUIC fields {quic_log_fields}")

                # Zscaler Contextual Variables
                # These are set regardless of whether IPs were found or not; _check_ip_in_ranges handles None IPs
                is_zscaler_ip_flag = _check_ip_in_ranges(source_ip, ZSCALER_EXAMPLE_IP_RANGES) or \
                                     _check_ip_in_ranges(destination_ip, ZSCALER_EXAMPLE_IP_RANGES)
                is_zpa_synthetic_ip_flag = _check_ip_in_ranges(source_ip, [ZPA_SYNTHETIC_IP_RANGE]) or \
                                           _check_ip_in_ranges(destination_ip, [ZPA_SYNTHETIC_IP_RANGE])

                # ssl_inspection_active: Still placeholder, requires cert parsing not yet implemented.
                # zscaler_policy_block_type
                if is_zscaler_ip_flag: # Only if one of the IPs is determined to be a Zscaler IP
                    is_zs_source = _check_ip_in_ranges(source_ip, ZSCALER_EXAMPLE_IP_RANGES)
                    if tcp_flags_rst and is_zs_source:
                        zscaler_policy_block_type_str = "TCP_RST_FROM_ZSCALER"
                    elif http_response_code_int and http_response_code_int >= 400 and is_zs_source:
                        if http_response_code_int == 403: zscaler_policy_block_type_str = "HTTP_403_FROM_ZSCALER"
                        elif http_response_code_int == 407: zscaler_policy_block_type_str = "HTTP_407_PROXY_AUTH_REQ_FROM_ZSCALER"
                        else: zscaler_policy_block_type_str = f"HTTP_{http_response_code_int}_FROM_ZSCALER"
                    elif tls_alert_level_str == "fatal" and tls_alert_description_str and is_zs_source:
                        safe_alert_desc = "".join(c if c.isalnum() or c in ['_'] else '_' for c in tls_alert_description_str)
                        zscaler_policy_block_type_str = f"TLS_FATAL_ALERT_FROM_ZSCALER_{safe_alert_desc[:30]}"


                cert_meta = _extract_certificate_metadata(packet)

                record_obj = PcapRecord(
                    frame_number=frame_number, timestamp=timestamp,
                    source_ip=source_ip, destination_ip=destination_ip,
                    source_port=source_port, destination_port=destination_port,
                    protocol=protocol_l4, sni=sni, raw_packet_summary=raw_summary,
                    source_mac=source_mac, destination_mac=destination_mac,
                    protocol_l3=protocol_l3, packet_length=packet_length_val,
                    ip_ttl=ip_ttl, ip_flags_df=ip_flags_df_bool, ip_id=ip_id_val, dscp_value=dscp_val,
                    tcp_flags_syn=tcp_flags_syn, tcp_flags_ack=tcp_flags_ack,
                    tcp_flags_fin=tcp_flags_fin, tcp_flags_rst=tcp_flags_rst,
                    tcp_flags_psh=tcp_flags_psh, tcp_flags_urg=tcp_flags_urg,
                    tcp_flags_ece=tcp_flags_ece, tcp_flags_cwr=tcp_flags_cwr,
                    tcp_sequence_number=tcp_sequence_number,
                    tcp_acknowledgment_number=tcp_acknowledgment_number,
                    tcp_window_size=tcp_window_size,
                    tcp_options_mss=tcp_options_mss,
                    tcp_options_sack_permitted=tcp_options_sack_permitted,
                    tcp_options_window_scale=tcp_options_window_scale,
                    tcp_stream_index=tcp_stream_index,
                    is_src_client=is_src_client_val,
                    tcp_analysis_retransmission_flags=tcp_analysis_retransmission_flags,
                    tcp_analysis_duplicate_ack_flags=tcp_analysis_duplicate_ack_flags,
                    tcp_analysis_out_of_order_flags=tcp_analysis_out_of_order_flags,
                    tcp_analysis_window_flags=tcp_analysis_window_flags,
                    dup_ack_num=dup_ack_num_val,
                    adv_window=adv_window_val,
                    tcp_rtt_ms=tcp_rtt_ms_sample,
                    tls_handshake_type=tls_handshake_type_str,
                    tls_handshake_version=tls_handshake_version_str,
                    tls_record_version=tls_record_version_str,
                    tls_effective_version=tls_effective_version_str,
                    tls_cipher_suites_offered=tls_cipher_suites_offered_list,
                    tls_cipher_suite_selected=tls_cipher_suite_selected_str,
                    tls_alert_message_description=tls_alert_description_str,
                    tls_alert_level=tls_alert_level_str,
                    dns_query_name=dns_query_name_str,
                    dns_query_type=dns_query_type_str,
                    dns_response_code=dns_response_code_str,
                    dns_response_addresses=dns_response_addresses_list,
                    dns_response_cname_target=dns_response_cname_target_str,
                    http_request_method=http_request_method_str,
                    http_request_uri=http_request_uri_str,
                    http_request_host_header=http_request_host_header_str,
                    http_response_code=http_response_code_int,
                    http_response_location_header=http_response_location_header_str,
                    http_x_forwarded_for_header=http_x_forwarded_for_header_str,
                    icmp_type=icmp_type_val,
                    icmp_code=icmp_code_val,
                    icmp_fragmentation_needed_original_mtu=icmp_frag_mtu_val,
                    arp_opcode=arp_opcode_val,
                    arp_sender_mac=arp_sender_mac_str,
                    arp_sender_ip=arp_sender_ip_str,
                    arp_target_mac=arp_target_mac_str,
                    arp_target_ip=arp_target_ip_str,
                    dhcp_message_type=dhcp_message_type_str,
                    gre_protocol=gre_protocol_str,
                    esp_spi=esp_spi_str,
                    quic_initial_packet_present=quic_initial_packet,
                    is_quic=is_quic_flag,
                    is_zscaler_ip=is_zscaler_ip_flag,
                    is_zpa_synthetic_ip=is_zpa_synthetic_ip_flag,
                    ssl_inspection_active=ssl_inspection_active_flag,
                    zscaler_policy_block_type=zscaler_policy_block_type_str,
                    **cert_meta,
                )
                yield record_obj
                generated_records += 1
            except AttributeError as ae: # This should be less common with _get_pyshark_layer_attribute
                logger.warning(
                    f"Frame {packet_count}: Attribute error processing packet details: {ae}. Packet Layers: {[layer.layer_name for layer in packet.layers if hasattr(layer, 'layer_name')]}",
                    exc_info=False,
                )  # exc_info=False to reduce noise if frequent
            except Exception as e_pkt: # Catch-all for other unexpected errors per packet
                logger.error(f"Frame {packet_count}: Error processing packet: {e_pkt}. Skipping.", exc_info=True) # Keep exc_info for unexpected

            if packet_count > 0 and packet_count % 1000 == 0 :
                logger.info(f"PyShark: Scanned {packet_count} packets...")
    except pyshark.capture.capture.TSharkCrashException as e_crash:
        logger.error(f"TShark crashed while processing {file_path}: {e_crash}")
        raise RuntimeError(f"TShark crashed, unable to process {file_path}.") from e_crash
    except Exception as e_cap_iter:
        logger.error(f"An error occurred during PyShark packet iteration in {file_path}: {e_cap_iter}", exc_info=True)
    finally:
        if cap: cap.close()
        logger.info(f"PyShark: Finished processing. Scanned {packet_count} packets, yielded {generated_records} records.")

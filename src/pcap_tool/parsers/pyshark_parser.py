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
        self._extract_misc_data(extractor, record)
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
        if record.tcp_flags_rst is None:
            record.tcp_flags_rst = ext.get("tcp", "flags_reset", record.frame_number, is_flag=True)
        record.tcp_flags_psh = ext.get("tcp", "flags_push", record.frame_number, is_flag=True)
        record.tcp_flags_urg = ext.get("tcp", "flags_urg", record.frame_number, is_flag=True)
        record.tcp_sequence_number = _safe_int(ext.get("tcp", "seq", record.frame_number))
        record.tcp_acknowledgment_number = _safe_int(ext.get("tcp", "ack", record.frame_number))
        record.tcp_window_size = _safe_int(ext.get("tcp", "window_size_value", record.frame_number))
        record.tcp_stream_index = _safe_int(ext.get("tcp", "stream", record.frame_number))

        flow_key = (record.source_ip, record.source_port, record.destination_ip, record.destination_port)
        orient_key = record.tcp_stream_index if record.tcp_stream_index is not None else flow_key
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

    def _extract_misc_data(self, ext: PacketExtractor, record: PcapRecord) -> None:
        """Extract miscellaneous fields like ICMP details and Zscaler flags."""

        icmp_layer = None
        if record.protocol == "ICMP" and hasattr(ext.packet, "icmp"):
            icmp_layer = ext.packet.icmp
        elif record.protocol == "ICMPv6" and hasattr(ext.packet, "icmpv6"):
            icmp_layer = ext.packet.icmpv6

        if icmp_layer is not None:
            record.icmp_type = _safe_int(_get_pyshark_layer_attribute(icmp_layer, "type", record.frame_number))
            record.icmp_code = _safe_int(_get_pyshark_layer_attribute(icmp_layer, "code", record.frame_number))

            frag_needed_v4 = record.protocol == "ICMP" and record.icmp_type == 3 and record.icmp_code == 4
            pkt_too_big_v6 = record.protocol == "ICMPv6" and record.icmp_type == 2 and record.icmp_code == 0
            if frag_needed_v4 or pkt_too_big_v6:
                mtu_str = _get_pyshark_layer_attribute(icmp_layer, "mtu", record.frame_number)
                if mtu_str is None and frag_needed_v4:
                    mtu_str = _get_pyshark_layer_attribute(icmp_layer, "nexthopmtu", record.frame_number)
                if mtu_str is not None:
                    record.icmp_fragmentation_needed_original_mtu = _safe_int(mtu_str)

        if record.source_ip is None and record.destination_ip is None:
            record.is_zscaler_ip = None
            record.is_zpa_synthetic_ip = None
        else:
            record.is_zscaler_ip = (
                _check_ip_in_ranges(record.source_ip, ZSCALER_EXAMPLE_IP_RANGES)
                or _check_ip_in_ranges(record.destination_ip, ZSCALER_EXAMPLE_IP_RANGES)
            )
            record.is_zpa_synthetic_ip = (
                _check_ip_in_ranges(record.source_ip, [ZPA_SYNTHETIC_IP_RANGE])
                or _check_ip_in_ranges(record.destination_ip, [ZPA_SYNTHETIC_IP_RANGE])
            )

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
        # Reset state for each parse invocation to avoid cross-file carryover
        self.flow_orientation.clear()
        self.tcp_syn_times.clear()
        self.tcp_rtt_samples.clear()

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

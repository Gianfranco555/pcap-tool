from __future__ import annotations
from typing import Generator, Optional

from pcap_tool.logging import get_logger
from dataclasses import asdict
from ..core.models import PcapRecord
from .base import BaseParser
from .utils import _safe_int
from ..core.decorators import handle_parse_errors, log_performance
from ..core.dependencies import container

logger = get_logger(__name__)

try:  # pragma: no cover - optional dependency check
    pcapkit = container.get("pcapkit")
    pcapkit_extract = pcapkit.extract
    USE_PCAPKIT = True
except ImportError:
    USE_PCAPKIT = False


class PcapkitParser(BaseParser):
    """Parser implementation using ``pcapkit``."""

    @classmethod
    def validate(cls) -> bool:  # pragma: no cover - simple availability check
        return USE_PCAPKIT

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
        return _parse_with_pcapkit(file_path, max_packets)


@handle_parse_errors
@log_performance
def _parse_with_pcapkit(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Attempting to parse with PCAPKit (fallback): {file_path}")
    logger.warning(
        "PCAPKit fallback: Most new fields are not implemented in this PcapKit path."
    )

    packet_count = 0
    generated_records = 0
    extractor = None

    try:
        extract_kwargs = {"fin": file_path, "store": False, "engine": pcapkit.PCAPKit}
        if "auto_protocol" in pcapkit_extract.__code__.co_varnames:
            extract_kwargs["auto_protocol"] = True
        else:
            extract_kwargs["auto"] = True

        extractor = pcapkit_extract(**extract_kwargs)
        for frame in extractor:
            packet_count += 1

            timestamp = float(getattr(frame.info, "time_epoch", 0.0))
            length = getattr(frame.info, "cap_len", None)

            row = {
                "frame_number": packet_count,
                "timestamp": timestamp,
                "packet_length": length,
            }
            record = PcapRecord.from_parser_row(row)

            eth = getattr(frame.info, "ethernet", None)
            ip_layer = None
            if eth is not None:
                record.source_mac = getattr(eth, "src", None)
                record.destination_mac = getattr(eth, "dst", None)

                if hasattr(eth, "ipv4"):
                    ipv4 = eth.ipv4
                    ip_layer = ipv4
                    record.protocol_l3 = "IPv4"
                    record.source_ip = getattr(ipv4, "src", None)
                    record.destination_ip = getattr(ipv4, "dst", None)
                    ttl_val = getattr(ipv4, "ttl", None)
                    if ttl_val is not None:
                        record.ip_ttl = int(ttl_val.total_seconds()) if hasattr(ttl_val, "total_seconds") else int(ttl_val)
                    proto = getattr(ipv4, "protocol", getattr(ipv4, "proto", None))
                    if proto is not None:
                        record.protocol = getattr(proto, "name", str(proto))

                elif hasattr(eth, "ipv6"):
                    ipv6 = eth.ipv6
                    ip_layer = ipv6
                    record.protocol_l3 = "IPv6"
                    record.source_ip = getattr(ipv6, "src", None)
                    record.destination_ip = getattr(ipv6, "dst", None)
                    ttl_val = (
                        getattr(ipv6, "limit", None)
                        or getattr(ipv6, "hop_limit", None)
                        or getattr(ipv6, "ttl", None)
                    )
                    if ttl_val is not None:
                        record.ip_ttl = int(ttl_val.total_seconds()) if hasattr(ttl_val, "total_seconds") else int(ttl_val)
                    proto = (
                        getattr(ipv6, "next_header", None)
                        or getattr(ipv6, "nxt", None)
                        or getattr(ipv6, "protocol", None)
                    )
                    if proto is not None:
                        record.protocol = getattr(proto, "name", str(proto))

                elif hasattr(eth, "arp"):
                    arp = eth.arp
                    record.protocol_l3 = "ARP"
                    record.arp_sender_mac = getattr(arp, "src_hw_mac", None)
                    record.arp_sender_ip = getattr(arp, "src_proto_ipv4", None)
                    record.arp_target_mac = getattr(arp, "dst_hw_mac", None)
                    record.arp_target_ip = getattr(arp, "dst_proto_ipv4", None)
                    record.arp_opcode = getattr(arp, "opcode", None)

            # ── L4 Processing ───────────────────────────────────────────────
            if record.protocol == "TCP":
                tcp_layer = None
                if hasattr(frame.info, "tcp"):
                    tcp_layer = frame.info.tcp
                elif ip_layer is not None and hasattr(ip_layer, "tcp"):
                    tcp_layer = ip_layer.tcp

                if tcp_layer is not None:
                    sport = getattr(tcp_layer, "source_port", None)
                    if sport is None:
                        sport = getattr(tcp_layer, "sport", None)
                    if sport is None:
                        sport = getattr(tcp_layer, "srcport", None)
                    if sport is not None:
                        record.source_port = _safe_int(sport)

                    dport = getattr(tcp_layer, "destination_port", None)
                    if dport is None:
                        dport = getattr(tcp_layer, "dport", None)
                    if dport is None:
                        dport = getattr(tcp_layer, "dstport", None)
                    if dport is not None:
                        record.destination_port = _safe_int(dport)

                    flags = getattr(tcp_layer, "flags", None)
                    if flags is not None:
                        record.tcp_flags_syn = getattr(flags, "syn", None)
                        record.tcp_flags_ack = getattr(flags, "ack", None)
                        record.tcp_flags_fin = getattr(flags, "fin", None)
                        record.tcp_flags_rst = getattr(flags, "rst", None)
                        record.tcp_flags_psh = getattr(flags, "psh", None)
                        record.tcp_flags_urg = getattr(flags, "urg", None)

                    seq_num = getattr(tcp_layer, "sequence_number", None)
                    if seq_num is None:
                        seq_num = getattr(tcp_layer, "seq", None)
                    if seq_num is not None:
                        record.tcp_sequence_number = _safe_int(seq_num)

                    ack_num = getattr(tcp_layer, "acknowledgment_number", None)
                    if ack_num is None:
                        ack_num = getattr(tcp_layer, "ack", None)
                    if ack_num is not None:
                        record.tcp_acknowledgment_number = _safe_int(ack_num)

                    win_size = getattr(tcp_layer, "window_size", None)
                    if win_size is None:
                        win_size = getattr(tcp_layer, "window", None)
                    if win_size is not None:
                        record.tcp_window_size = _safe_int(win_size)

            elif record.protocol == "UDP":
                udp_layer = None
                if hasattr(frame.info, "udp"):
                    udp_layer = frame.info.udp
                elif ip_layer is not None and hasattr(ip_layer, "udp"):
                    udp_layer = ip_layer.udp

                if udp_layer is not None:
                    sport = getattr(udp_layer, "source_port", None)
                    if sport is None:
                        sport = getattr(udp_layer, "sport", None)
                    if sport is None:
                        sport = getattr(udp_layer, "srcport", None)
                    if sport is not None:
                        record.source_port = _safe_int(sport)

                    dport = getattr(udp_layer, "destination_port", None)
                    if dport is None:
                        dport = getattr(udp_layer, "dport", None)
                    if dport is None:
                        dport = getattr(udp_layer, "dstport", None)
                    if dport is not None:
                        record.destination_port = _safe_int(dport)

            elif record.protocol == "ICMP":
                icmp_layer = (
                    getattr(frame.info, "icmpv4", None)
                    or getattr(frame.info, "icmp", None)
                )
                if icmp_layer is not None:
                    msg = getattr(icmp_layer, "message", icmp_layer)
                    icmp_type = getattr(msg, "type", None)
                    icmp_code = getattr(msg, "code", None)
                    if icmp_type is not None:
                        record.icmp_type = _safe_int(icmp_type)
                    if icmp_code is not None:
                        record.icmp_code = _safe_int(icmp_code)

            elif record.protocol == "ICMPv6":
                icmp6_layer = getattr(frame.info, "icmpv6", None)
                if icmp6_layer is not None:
                    msg = getattr(icmp6_layer, "message", icmp6_layer)
                    icmp_type = getattr(msg, "type", None)
                    icmp_code = getattr(msg, "code", None)
                    if icmp_type is not None:
                        record.icmp_type = _safe_int(icmp_type)
                    if icmp_code is not None:
                        record.icmp_code = _safe_int(icmp_code)

            yield PcapRecord.from_parser_row(asdict(record))

            generated_records += 1
            if max_packets is not None and generated_records >= max_packets:
                logger.info(
                    f"PCAPKit: Reached max_packets limit of {max_packets}."
                )
                break
    except Exception as e_capkit:
        logger.error(
            f"An error occurred during PCAPKit packet iteration in {file_path}: {e_capkit}",
            exc_info=True,
        )
    finally:
        if extractor is not None and not getattr(extractor, "_flag_e", False):
            try:
                extractor._cleanup()  # type: ignore[attr-defined]
            except Exception:
                pass
        logger.info(
            f"PCAPKit: Finished processing. Scanned {packet_count} packets, yielded {generated_records} records."
        )

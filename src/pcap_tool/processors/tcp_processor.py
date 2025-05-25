from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, Optional, TYPE_CHECKING

from ..models import PcapRecord
from ..parsers.utils import _safe_int
from . import PacketProcessor

if TYPE_CHECKING:  # pragma: no cover - type hints only
    from ..parsers.pyshark_parser import PacketExtractor

_TCP_FLOW_HISTORY: Dict[tuple[str, int, str, int], deque] = defaultdict(deque)
_TCP_FLOW_HISTORY_MAX = 64


def _flow_history_key(src_ip: Optional[str], src_port: Optional[int], dst_ip: Optional[str], dst_port: Optional[int]) -> tuple[str, int, str, int]:
    return (
        src_ip or "",
        src_port or -1,
        dst_ip or "",
        dst_port or -1,
    )


def _update_flow_history(key: tuple[str, int, str, int], seq: Optional[int], ack: Optional[int], win: Optional[int], length: int) -> None:
    hist = _TCP_FLOW_HISTORY[key]
    hist.append({"seq": seq, "ack": ack, "win": win, "len": length})
    if len(hist) > _TCP_FLOW_HISTORY_MAX:
        hist.popleft()


def _heuristic_tcp_flags(key: tuple[str, int, str, int], seq: Optional[int], ack: Optional[int], win: Optional[int], length: int) -> Dict[str, bool]:
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


class TCPProcessor(PacketProcessor):
    """Handle TCP specific extraction and analysis."""

    def __init__(self) -> None:
        self.flow_orientation: Dict[Any, tuple[str | None, int | None]] = {}
        self.tcp_syn_times: Dict[tuple[str, int, str, int, str], float] = {}
        self.tcp_rtt_samples: defaultdict[tuple[str, int, str, int, str], list[float]] = defaultdict(list)

    def reset(self) -> None:
        self.flow_orientation.clear()
        self.tcp_syn_times.clear()
        self.tcp_rtt_samples.clear()

    def process_packet(self, extractor: "PacketExtractor", record: PcapRecord) -> Dict[str, Any]:
        result: Dict[str, Any] = {}

        if record.protocol != "TCP" or not hasattr(extractor.packet, "tcp"):
            if record.protocol == "UDP" and record.destination_port is None:
                result["source_port"] = _safe_int(extractor.get("udp", "srcport", record.frame_number))
                result["destination_port"] = _safe_int(extractor.get("udp", "dstport", record.frame_number))
                if result.get("destination_port") == 443:
                    result["is_quic"] = bool(hasattr(extractor.packet, "quic"))
            return {k: v for k, v in result.items() if v is not None}

        src_port = _safe_int(extractor.get("tcp", "srcport", record.frame_number))
        dst_port = _safe_int(extractor.get("tcp", "dstport", record.frame_number))
        result.update(
            source_port=src_port,
            destination_port=dst_port,
            tcp_flags_syn=extractor.get("tcp", "flags_syn", record.frame_number, is_flag=True),
            tcp_flags_ack=extractor.get("tcp", "flags_ack", record.frame_number, is_flag=True),
            tcp_flags_fin=extractor.get("tcp", "flags_fin", record.frame_number, is_flag=True),
            tcp_flags_rst=extractor.get("tcp", "flags_rst", record.frame_number, is_flag=True),
            tcp_flags_psh=extractor.get("tcp", "flags_push", record.frame_number, is_flag=True),
            tcp_flags_urg=extractor.get("tcp", "flags_urg", record.frame_number, is_flag=True),
            tcp_sequence_number=_safe_int(extractor.get("tcp", "seq", record.frame_number)),
            tcp_acknowledgment_number=_safe_int(extractor.get("tcp", "ack", record.frame_number)),
            tcp_window_size=_safe_int(extractor.get("tcp", "window_size_value", record.frame_number)),
            tcp_stream_index=_safe_int(extractor.get("tcp", "stream", record.frame_number)),
        )

        if result["tcp_flags_rst"] is None:
            result["tcp_flags_rst"] = extractor.get("tcp", "flags_reset", record.frame_number, is_flag=True)

        flow_key = (record.source_ip, src_port, record.destination_ip, dst_port)
        orient_key = result["tcp_stream_index"] if result["tcp_stream_index"] is not None else flow_key
        orient = self.flow_orientation.get(orient_key)
        if orient is None and result.get("tcp_flags_syn") and not result.get("tcp_flags_ack"):
            orient = (record.source_ip, src_port)
            self.flow_orientation[orient_key] = orient
        if orient is not None:
            result["is_src_client"] = record.source_ip == orient[0] and src_port == orient[1]

        if result.get("tcp_flags_syn") and not result.get("tcp_flags_ack"):
            rtt_key = (
                record.source_ip or "",
                src_port or -1,
                record.destination_ip or "",
                dst_port or -1,
                "TCP",
            )
            if record.source_ip and record.destination_ip and src_port is not None and dst_port is not None:
                self.tcp_syn_times[rtt_key] = record.timestamp
        elif result.get("tcp_flags_syn") and result.get("tcp_flags_ack"):
            rtt_key_rev = (
                record.destination_ip or "",
                dst_port or -1,
                record.source_ip or "",
                src_port or -1,
                "TCP",
            )
            syn_ts = self.tcp_syn_times.pop(rtt_key_rev, None)
            if syn_ts is not None:
                result["tcp_rtt_ms"] = (record.timestamp - syn_ts) * 1000.0
                self.tcp_rtt_samples[rtt_key_rev].append(result["tcp_rtt_ms"])

        analysis_layer = getattr(extractor.packet.tcp, "analysis", None)

        def _get_analysis_attr(attr: str) -> Any:
            if analysis_layer and hasattr(analysis_layer, attr):
                return getattr(analysis_layer, attr)
            return getattr(extractor.packet.tcp, f"analysis_{attr}", None)

        adv_window_val = result.get("tcp_window_size") or _safe_int(extractor.get("tcp", "window_size", record.frame_number))
        payload_len_int = _safe_int(extractor.get("tcp", "len", record.frame_number)) or 0

        retrans_flags: list[str] = []
        dup_flags: list[str] = []
        oo_flags: list[str] = []
        win_flags: list[str] = []

        if _get_analysis_attr("retransmission") is not None:
            retrans_flags.append("retransmission")
        if _get_analysis_attr("fast_retransmission") is not None:
            retrans_flags.append("fast_retransmission")
            if result.get("dup_ack_num") is None:
                result["dup_ack_num"] = 3
        if _get_analysis_attr("spurious_retransmission") is not None:
            retrans_flags.append("spurious_retransmission")

        if _get_analysis_attr("duplicate_ack") is not None:
            dup_flags.append("duplicate_ack")
        dup_num_raw = _get_analysis_attr("duplicate_ack_num")
        if dup_num_raw is not None:
            val = _safe_int(dup_num_raw)
            if val is not None:
                result["dup_ack_num"] = val
                dup_flags.append(f"duplicate_ack_num:{val}")
            else:
                dup_flags.append("duplicate_ack_num")

        if _get_analysis_attr("out_of_order") is not None:
            oo_flags.append("out_of_order")
        if _get_analysis_attr("lost_segment") is not None:
            oo_flags.append("lost_segment")

        if _get_analysis_attr("zero_window") is not None:
            win_flags.append("zero_window")
        if _get_analysis_attr("zero_window_probe") is not None:
            if "zero_window" not in win_flags:
                win_flags.append("zero_window")
            win_flags.append("zero_window_probe")
        if _get_analysis_attr("zero_window_probe_ack") is not None:
            if "zero_window" not in win_flags:
                win_flags.append("zero_window")
            win_flags.append("zero_window_probe_ack")
        if _get_analysis_attr("window_update") is not None:
            win_flags.append("window_update")

        if not analysis_layer:
            key = _flow_history_key(record.source_ip, src_port, record.destination_ip, dst_port)
            h_flags = _heuristic_tcp_flags(key, result.get("tcp_sequence_number"), result.get("tcp_acknowledgment_number"), adv_window_val, payload_len_int)
            if h_flags["retransmission"]:
                retrans_flags.append("heuristic_retransmission")
            if h_flags["duplicate_ack"]:
                dup_flags.append("heuristic_duplicate_ack")
            if h_flags["out_of_order"]:
                oo_flags.append("heuristic_out_of_order")
            if h_flags["zero_window"]:
                win_flags.append("heuristic_zero_window")

        result["tcp_analysis_retransmission_flags"] = retrans_flags
        result["tcp_analysis_duplicate_ack_flags"] = dup_flags
        result["tcp_analysis_out_of_order_flags"] = oo_flags
        result["tcp_analysis_window_flags"] = win_flags
        result["adv_window"] = adv_window_val

        return {k: v for k, v in result.items() if v is not None or k.endswith("_flags")}


__all__ = ["TCPProcessor"]

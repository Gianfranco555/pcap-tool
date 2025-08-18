from __future__ import annotations

"""Lightweight flow modelling utilities.

This module defines simple data structures that identify a flow and expose
minimal bookkeeping for packet direction and handshake detection.  The goal is
to provide deterministic flow IDs that remain stable across runs while also
capturing which endpoint acted as the client or server.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from ..core.models import PcapRecord


# ---------------------------------------------------------------------------
# ``FlowKey`` and ``FlowId``
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowKey:
    """Canonical 5‑tuple identifying a flow.

    The tuple is ordered ``(client_ip, client_port, server_ip, server_port,
    l4_proto)``.  ``Flow.from_packets`` determines which host is the client
    using TCP SYN packets when available and otherwise falling back to the
    lower port number.
    """

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    l4_proto: str


# ``FlowId`` is just a type alias for clarity.
FlowId = str


def _build_flow_id(key: FlowKey, start_ts: float) -> FlowId:
    """Return a deterministic flow identifier.

    ``start_ts`` is formatted with a fixed precision to ensure stable string
    representations across Python versions.
    """

    return FlowId(
        f"{key.l4_proto}:{key.src_ip}:{key.src_port}->"
        f"{key.dst_ip}:{key.dst_port}#{start_ts:.6f}"
    )


# ---------------------------------------------------------------------------
# ``Flow`` dataclass
# ---------------------------------------------------------------------------


@dataclass
class Flow:
    """Container holding packets that belong to a single network flow."""

    id: FlowId
    key: FlowKey
    packets: List[PcapRecord] = field(default_factory=list)
    start_ts: float = 0.0
    end_ts: float = 0.0
    protocol: str = ""
    handshake_complete: bool = False
    client_is_src: Optional[bool] = None
    c2s_bytes: int = 0
    c2s_packets: int = 0
    s2c_bytes: int = 0
    s2c_packets: int = 0

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_packets(cls, packets: List[PcapRecord]) -> "Flow":
        """Create a :class:`Flow` from a list of packets.

        The packets are analysed to determine client/server roles and basic
        handshake information.  The resulting ``Flow`` has a deterministic
        identifier derived from the canonicalised key and ``start_ts`` of the
        capture.
        """

        if not packets:
            raise ValueError("packets required")

        packets_sorted = sorted(packets, key=lambda p: p.timestamp)
        first = packets_sorted[0]
        start_ts = first.timestamp
        end_ts = packets_sorted[-1].timestamp
        proto = first.protocol.upper()

        (
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_is_src,
        ) = cls._derive_roles(packets_sorted)

        key = FlowKey(
            src_ip=client_ip,
            src_port=client_port,
            dst_ip=server_ip,
            dst_port=server_port,
            l4_proto=proto,
        )
        fid = _build_flow_id(key, start_ts)

        c2s_bytes = c2s_packets = s2c_bytes = s2c_packets = 0
        syn = synack = final_ack = False

        for pkt in packets_sorted:
            if pkt.source_ip == client_ip and pkt.source_port == client_port:
                c2s_packets += 1
                c2s_bytes += pkt.packet_length
                if pkt.protocol.upper() == "TCP":
                    if pkt.tcp_flags_syn and not pkt.tcp_flags_ack:
                        syn = True
                    if synack and pkt.tcp_flags_ack and not pkt.tcp_flags_syn:
                        final_ack = True
            elif pkt.source_ip == server_ip and pkt.source_port == server_port:
                s2c_packets += 1
                s2c_bytes += pkt.packet_length
                if pkt.protocol.upper() == "TCP" and pkt.tcp_flags_syn and pkt.tcp_flags_ack:
                    synack = True

        handshake_complete = syn and synack and final_ack

        return cls(
            id=fid,
            key=key,
            packets=packets_sorted,
            start_ts=start_ts,
            end_ts=end_ts,
            protocol=proto,
            handshake_complete=handshake_complete,
            client_is_src=client_is_src,
            c2s_bytes=c2s_bytes,
            c2s_packets=c2s_packets,
            s2c_bytes=s2c_bytes,
            s2c_packets=s2c_packets,
        )

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_roles(packets: List[PcapRecord]) -> tuple[str, int, str, int, Optional[bool]]:
        """Determine client/server endpoints for ``packets``.

        The search prefers a TCP SYN packet which unambiguously marks the
        client's direction.  If no such packet is present, the endpoint with
        the lower port number is assumed to be the server.
        """

        first = packets[0]

        for pkt in packets:
            if (
                pkt.protocol.upper() == "TCP"
                and pkt.tcp_flags_syn
                and not pkt.tcp_flags_ack
            ):
                client_ip = pkt.source_ip
                client_port = pkt.source_port
                server_ip = pkt.destination_ip
                server_port = pkt.destination_port
                client_is_src = (
                    client_ip == first.source_ip and client_port == first.source_port
                )
                return (client_ip, client_port, server_ip, server_port, client_is_src)

        # Fallback: lower port is assumed server
        if first.source_port < first.destination_port:
            # Source has the lower port so is assumed to be the server
            client_ip, client_port = first.destination_ip, first.destination_port
            server_ip, server_port = first.source_ip, first.source_port
            client_is_src = False
        elif first.source_port > first.destination_port:
            client_ip, client_port = first.source_ip, first.source_port
            server_ip, server_port = first.destination_ip, first.destination_port
            client_is_src = True
        else:  # ports are equal – direction unknown
            client_ip, client_port = first.source_ip, first.source_port
            server_ip, server_port = first.destination_ip, first.destination_port
            client_is_src = None

        return (client_ip, client_port, server_ip, server_port, client_is_src)


__all__ = ["FlowKey", "FlowId", "Flow"]

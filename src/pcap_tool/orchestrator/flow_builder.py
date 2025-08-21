from __future__ import annotations

"""Utilities for turning packets into higher level flows.

This module implements :class:`FlowBuilder`, a small stateful helper that
aggregates :class:`~pcap_tool.core.models.PcapRecord` objects into
``Flow`` instances.  Flows are emitted once they are deemed complete –
when a TCP connection is closed via FIN/ACK, a RST is seen or the flow has
been idle for longer than the configured timeout.
"""

from dataclasses import dataclass, field
from heapq import heappop, heappush
from typing import Dict, Iterable, List, Tuple

from ..core.models import PcapRecord
from .flow_models import Flow


# ---------------------------------------------------------------------------
# Internal flow state tracking
# ---------------------------------------------------------------------------


Endpoint = Tuple[str, int]
StateKey = Tuple[str, Endpoint, Endpoint]


@dataclass
class _FlowState:
    """Bookkeeping for a single in‑flight flow."""

    packets: List[PcapRecord] = field(default_factory=list)
    last_seen: float = 0.0
    fin_from: set[str] = field(default_factory=set)  # 'a' or 'b'
    awaiting_final_ack: bool = False
    rst_seen: bool = False


# ---------------------------------------------------------------------------
# ``FlowBuilder``
# ---------------------------------------------------------------------------


class FlowBuilder:
    """Incrementally build network flows from packets.

    Parameters
    ----------
    timeout_s:
        Idle timeout in seconds after which a flow is considered finished
        if no packets have been observed.
    """

    def __init__(self, timeout_s: float = 60) -> None:
        self.timeout_s = timeout_s
        self._flows: Dict[StateKey, _FlowState] = {}
        self._last_seen_heap: List[Tuple[float, StateKey]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, pkt: PcapRecord) -> Iterable[Flow]:
        """Observe ``pkt`` and yield any flows that completed as a result.

        Packets are expected to be provided in chronological order.  Feeding
        out‑of‑order timestamps may lead to premature or delayed timeouts.

        The returned iterable may contain zero or more ``Flow`` objects.
        Flows can be completed because the current packet closed a TCP
        connection (FIN/ACK or RST) or because unrelated flows timed out
        prior to handling this packet.
        """

        completed: List[Flow] = []

        # First emit flows that have exceeded the idle timeout.
        completed.extend(self._expire_idle(pkt.timestamp))

        key, direction = self._key(pkt)
        state = self._flows.get(key)
        if state is None:
            state = _FlowState()
            self._flows[key] = state

        state.packets.append(pkt)
        state.last_seen = pkt.timestamp
        heappush(self._last_seen_heap, (state.last_seen, key))

        if pkt.protocol.upper() == "TCP":
            if pkt.tcp_flags_rst:
                state.rst_seen = True
                completed.append(self._finalise(key))
                return completed

            if pkt.tcp_flags_fin:
                state.fin_from.add(direction)
                # After both FINs we wait for the final ACK (ACK without FIN)
                if len(state.fin_from) == 2:
                    state.awaiting_final_ack = True

            if (
                state.awaiting_final_ack
                and pkt.tcp_flags_ack
                and not pkt.tcp_flags_fin
                and not pkt.tcp_flags_rst
            ):
                completed.append(self._finalise(key))

        return completed

    def flush_all(self) -> Iterable[Flow]:
        """Flush and return all currently tracked flows."""

        completed: List[Flow] = []
        for key in list(self._flows.keys()):
            completed.append(self._finalise(key))
        self._last_seen_heap.clear()
        return completed

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _key(self, pkt: PcapRecord) -> Tuple[StateKey, str]:
        """Return a canonical key for ``pkt`` and the packet direction.

        The direction is ``'a'`` when the packet's source corresponds to the
        first endpoint in the key and ``'b'`` otherwise.  Endpoints are
        ordered to ensure packets from both directions map to the same key
        regardless of who is the client or server.
        """

        proto = pkt.protocol.upper()
        a: Endpoint = (pkt.source_ip, pkt.source_port)
        b: Endpoint = (pkt.destination_ip, pkt.destination_port)
        if a <= b:
            key = (proto, a, b)
            direction = "a"
        else:
            key = (proto, b, a)
            direction = "b"
        return key, direction

    def _finalise(self, key: StateKey) -> Flow:
        """Create a :class:`Flow` from accumulated packets and remove state."""

        state = self._flows.pop(key)
        return Flow.from_packets(state.packets)

    def _expire_idle(self, current_ts: float) -> List[Flow]:
        """Emit flows whose last activity is older than ``timeout_s``."""

        expired: List[Flow] = []
        threshold = current_ts - self.timeout_s
        while self._last_seen_heap and self._last_seen_heap[0][0] <= threshold:
            last_seen, key = heappop(self._last_seen_heap)
            state = self._flows.get(key)
            if state is None or state.last_seen != last_seen:
                continue
            expired.append(self._finalise(key))
        return expired


__all__ = ["FlowBuilder"]

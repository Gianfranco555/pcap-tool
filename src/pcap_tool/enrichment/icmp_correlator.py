from __future__ import annotations

import pandas as pd
from typing import Dict, Tuple, Any, Optional, DefaultDict
from collections import defaultdict


FlowKey = Tuple[Optional[str], Optional[str], Optional[int], Optional[int], Optional[str]]
PacketKey = Tuple[Optional[str], Optional[int], Optional[str], Any]


def correlate_icmp_errors(packets: pd.DataFrame, flows: pd.DataFrame) -> pd.DataFrame:
    """Update ``flows`` with counts of downstream ICMP errors.

    The ``packets`` DataFrame should contain packet level records with at least
    the following columns when available:

    ``source_ip``
        Source IP address of the packet.
    ``destination_ip``
        Destination IP address of the packet.
    ``source_port``
        Source port number for TCP/UDP packets.
    ``destination_port``
        Destination port number for TCP/UDP packets.
    ``protocol``
        L4 protocol name (e.g. ``TCP``, ``UDP``).
    ``ip_id``
        IP identifier for IPv4 packets.
    ``is_source_client`` or ``is_src_client``
        Boolean indicating packet direction relative to the client.

    For ICMP error packets the following columns are consulted to identify the
    original packet that triggered the error:

    ``icmp_original_destination_ip``
    ``icmp_original_destination_port``
    ``icmp_original_protocol``
    ``icmp_original_ip_id``

    ``flows`` must include a ``flow_id`` column along with ``client_ip``,
    ``server_ip``, ``client_port``, ``server_port`` and ``protocol``. An
    ``icmp_error_count`` column will be added if not present.
    """

    if flows.empty or "flow_id" not in flows.columns:
        return flows

    df = flows.copy()
    if "icmp_error_count" not in df.columns:
        df["icmp_error_count"] = 0

    # Build lookup from flow tuple to flow_id for both directions
    flow_lookup: Dict[FlowKey, int] = {}
    for row in df.itertuples(index=False):
        key_fwd = (
            row.client_ip,
            row.server_ip,
            row.client_port,
            row.server_port,
            str(row.protocol).upper() if row.protocol is not None else None,
        )
        key_rev = (
            row.server_ip,
            row.client_ip,
            row.server_port,
            row.client_port,
            str(row.protocol).upper() if row.protocol is not None else None,
        )
        flow_lookup[key_fwd] = row.flow_id
        flow_lookup[key_rev] = row.flow_id

    df = df.set_index("flow_id")

    # Track live packets by destination tuple + ip_id
    packet_map: Dict[PacketKey, int] = {}
    error_counts: DefaultDict[int, int] = defaultdict(int)

    def _get_direction_flag(r: Any) -> Any:
        return getattr(r, "is_source_client", getattr(r, "is_src_client", None))

    for r in packets.itertuples(index=False):
        proto = str(getattr(r, "protocol", "")).upper()
        if proto in {"ICMP", "ICMPV6"}:
            icmp_type = getattr(r, "icmp_type", None)
            if icmp_type not in {3, 11}:
                continue
            orig_dst = getattr(r, "icmp_original_destination_ip", None)
            orig_dport = getattr(r, "icmp_original_destination_port", None)
            orig_proto = getattr(r, "icmp_original_protocol", None)
            orig_ipid = getattr(r, "icmp_original_ip_id", None)
            key = (
                orig_dst,
                orig_dport,
                str(orig_proto).upper() if orig_proto else None,
                orig_ipid,
            )
            fid = packet_map.get(key)
            if fid is not None:
                error_counts[fid] += 1
            continue

        direction = _get_direction_flag(r)
        if direction is None:
            continue
        if direction:
            key_flow = (
                getattr(r, "source_ip", None),
                getattr(r, "destination_ip", None),
                getattr(r, "source_port", None),
                getattr(r, "destination_port", None),
                proto,
            )
        else:
            key_flow = (
                getattr(r, "destination_ip", None),
                getattr(r, "source_ip", None),
                getattr(r, "destination_port", None),
                getattr(r, "source_port", None),
                proto,
            )
        fid = flow_lookup.get(key_flow)
        if fid is not None:
            pkt_key = (
                getattr(r, "destination_ip", None),
                getattr(r, "destination_port", None),
                proto,
                getattr(r, "ip_id", None),
            )

            packet_map[pkt_key] = fid

    for fid, count in error_counts.items():
        if fid in df.index:
            df.loc[fid, "icmp_error_count"] += count
    return df.reset_index()

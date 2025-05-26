from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict, Tuple, Union


class FlowKey(TypedDict):
    """Identifier for a network flow."""

    src_ip: Optional[str]
    dest_ip: Optional[str]
    src_port: Optional[int]
    dest_port: Optional[int]
    protocol: Optional[str]


class PacketData(TypedDict, total=False):
    """Basic packet information."""

    frame_number: int
    timestamp: float
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]


class AnalysisResult(TypedDict, total=False):
    """Typed representation of aggregated analysis metrics."""

    capture_info: Dict[str, Any]
    protocols: Dict[str, Any]
    top_ports: Dict[str, Any]
    quic_vs_tls_packets: Dict[str, Any]
    tls_version_counts: Dict[str, Any]
    top_talkers_by_bytes: List[Dict[str, Any]]
    top_talkers_by_packets: List[Dict[str, Any]]
    service_overview: Dict[str, Any]
    error_summary: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    security_findings: Dict[str, Any]
    timeline_data: List[Dict[str, Any]]
    top_flows: List[Dict[str, Any]]


FlowKeyTuple = Tuple[Optional[str], Optional[str], Optional[int], Optional[int], Optional[str]]
PacketList = List[PacketData]
JSONDict = Dict[str, Any]

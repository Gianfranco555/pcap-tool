
"""Placeholder utilities for heuristic metrics aggregation."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Mapping, Dict, Any

from ..parser import PcapRecord


def count_tls_versions(records: Iterable[Any]) -> Dict[str, int]:
    """Return counts of observed TLS versions."""
    counts: defaultdict[str, int] = defaultdict(int)
    for rec in records:
        version = None
        if isinstance(rec, PcapRecord):
            version = rec.tls_effective_version
        elif isinstance(rec, Mapping):
            version = rec.get("tls_effective_version")
        else:
            version = getattr(rec, "tls_effective_version", None)
        if version:
            counts[str(version)] += 1
    return dict(counts)

from typing import List, Optional
import numpy as np


def compute_tcp_rtt_stats(flow_rtt_samples: List[float]) -> Dict[str, Optional[float | int | str]]:
    """Return summary statistics for a list of RTT samples in milliseconds."""
    if not flow_rtt_samples:
        return {
            "median": None,
            "p95": None,
            "min": None,
            "max": None,
            "samples": 0,
            "reason": "insufficient_syn_ack_pairs",
        }

    arr = np.array(flow_rtt_samples, dtype=float)
    return {
        "median": float(np.median(arr)),
        "p95": float(np.percentile(arr, 95)),
        "min": float(arr.min()),
        "max": float(arr.max()),
        "samples": len(flow_rtt_samples),
    }

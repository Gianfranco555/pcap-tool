"""Placeholder utilities for heuristic metrics aggregation."""

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

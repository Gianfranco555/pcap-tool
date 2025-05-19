from __future__ import annotations

from typing import List, Dict, Optional
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

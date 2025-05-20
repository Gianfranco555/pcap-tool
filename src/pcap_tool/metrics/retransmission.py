"""Helpers for analyzing TCP retransmission ratios."""

from __future__ import annotations


def categorize_retransmission_severity(ratio: float) -> dict[str, str]:
    """Return a status label and color based on ``ratio``.

    Parameters
    ----------
    ratio:
        TCP retransmission ratio as a percentage.
    """
    if ratio < 1.0:
        return {"status": "Healthy", "color": "#28a745"}
    if ratio <= 3.0:
        return {"status": "Warning", "color": "#ffc107"}
    return {"status": "Critical", "color": "#dc3545"}

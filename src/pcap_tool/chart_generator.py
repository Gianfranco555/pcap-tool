"""Simple chart generation helpers for PDF reports."""

from __future__ import annotations

from io import BytesIO
from typing import Dict


def protocol_pie_chart(protocol_counts: Dict[str, int]) -> bytes:
    """Return a pie chart image for protocol distribution."""
    if not protocol_counts:
        return b""
    try:
        import matplotlib.pyplot as plt
    except Exception:  # pragma: no cover - optional dependency
        return b""
    labels = list(protocol_counts.keys())
    sizes = list(protocol_counts.values())
    fig, ax = plt.subplots(figsize=(2, 2))
    ax.pie(sizes, labels=labels, autopct="%1.1f%%")
    buf = BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    return buf.getvalue()


def top_ports_bar_chart(port_counts: Dict[str, int]) -> bytes:
    """Return a bar chart image for top TCP/UDP ports."""
    if not port_counts:
        return b""
    try:
        import matplotlib.pyplot as plt
    except Exception:  # pragma: no cover - optional dependency
        return b""
    labels = list(port_counts.keys())
    values = list(port_counts.values())
    fig, ax = plt.subplots(figsize=(3, 2))
    ax.bar(labels, values)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    buf = BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    return buf.getvalue()

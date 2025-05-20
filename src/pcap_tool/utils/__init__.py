from __future__ import annotations

import pandas as pd

from .pandas_safe import coalesce, safe_int
from .net import anonymize_ip


def export_to_csv(data_to_export: pd.DataFrame, filename: str) -> None:
    """Write ``data_to_export`` to ``filename`` as CSV without index."""
    data_to_export.to_csv(filename, index=False)


def safe_int_or_default(value: object, default: int = 0) -> int:
    """Return ``int(value)`` unless ``value`` is ``NaN`` or ``None``.

    Parameters
    ----------
    value:
        Value to convert.
    default:
        Fallback if ``value`` is missing or cannot be converted.
    """
    if pd.notna(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    return default

__all__ = [
    "export_to_csv",
    "safe_int_or_default",
    "safe_int",
    "coalesce",
    "anonymize_ip",
]

from __future__ import annotations

from typing import Any, Optional


def _safe_str_to_bool(value: Any) -> Optional[bool]:
    """Safely converts a string value (like '0', '1', 'true', 'false') to ``bool``."""
    if isinstance(value, bool):
        return value
    s_val = str(value).lower().strip()
    if s_val in {"true", "1"}:
        return True
    if s_val in {"false", "0"}:
        return False
    return None


def _safe_int(value: Any) -> Optional[int]:
    """Safely convert ``value`` containing commas or prefixes to ``int``."""
    try:
        cleaned = str(value).replace(",", "")
        return int(cleaned, 0)
    except (TypeError, ValueError):
        return None

__all__ = ["_safe_int", "_safe_str_to_bool"]

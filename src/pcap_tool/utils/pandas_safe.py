import pandas as pd


def safe_int(series: pd.Series, default: int = 0) -> pd.Series:
    """Return integer Series with ``NaN`` replaced by ``default``.

    Parameters
    ----------
    series:
        Series to convert.
    default:
        Value to use where ``series`` has ``NaN``.
    """
    filled = series.where(series.notna(), default)
    if hasattr(filled, "infer_objects"):
        filled = filled.infer_objects(copy=False)
    return pd.to_numeric(filled, downcast="integer")


def coalesce(series: pd.Series, fallback):
    """Return ``series`` with ``NaN`` replaced by ``fallback``."""
    return series.where(series.notna(), fallback)

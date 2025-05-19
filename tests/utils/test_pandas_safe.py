import pandas as pd

from pcap_tool.utils import safe_int, coalesce


def test_safe_int_basic():
    series = pd.Series([1, pd.NA, 3])
    result = safe_int(series, default=0)
    assert result.tolist() == [1, 0, 3]
    assert result.dtype.kind in {"i", "u"}


def test_coalesce_basic():
    series = pd.Series(["a", pd.NA, "b"])
    result = coalesce(series, "x")
    assert result.tolist() == ["a", "x", "b"]

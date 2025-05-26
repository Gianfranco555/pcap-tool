from __future__ import annotations

from typing import Any, Iterable

import pandas as pd


def assert_packet_fields(pkt: Any, **expected: Any) -> None:
    """Assert that packet has specific field values."""
    for field, value in expected.items():
        assert getattr(pkt, field) == value, f"{field} != {value}"


def assert_flow_layers(packets: Iterable, layers: Iterable) -> None:
    """Assert each packet has expected layer."""
    for pkt, layer in zip(packets, layers):
        assert pkt.haslayer(layer)


def assert_frames_equal(left: pd.DataFrame, right: pd.DataFrame, ignore_index: bool = True) -> None:
    """Wrapper around pandas testing for DataFrame equality."""
    if ignore_index:
        left = left.reset_index(drop=True)
        right = right.reset_index(drop=True)
    pd.testing.assert_frame_equal(left, right, check_dtype=False)

"""Tests for :class:`PcapRecord` default handling and coercion."""

from __future__ import annotations

import math

from pcap_tool.core.models import PcapRecord


def test_missing_fields_defaults() -> None:
    """Missing fields should fall back to sane defaults."""

    record = PcapRecord.from_parser_row({})
    assert record.frame_number == 0
    assert record.timestamp == 0.0
    assert record.source_ip == ""
    assert record.source_port == 0
    assert record.tcp_flags_syn is False


def test_nan_values_coerced() -> None:
    """NaN values are coerced to defaults."""

    row = {
        "frame_number": float("nan"),
        "timestamp": float("nan"),
        "source_ip": float("nan"),
        "source_port": float("nan"),
        "tcp_flags_syn": float("nan"),
    }
    record = PcapRecord.from_parser_row(row)
    assert record.frame_number == 0
    assert record.timestamp == 0.0
    assert record.source_ip == ""
    assert record.source_port == 0
    assert record.tcp_flags_syn is False


def test_wrong_dtypes_coerced() -> None:
    """String representations are coerced to the correct types."""

    row = {
        "frame_number": "10",
        "timestamp": "20.5",
        "source_port": "80",
        "tcp_flags_syn": "True",
    }
    record = PcapRecord.from_parser_row(row)
    assert record.frame_number == 10
    assert math.isclose(record.timestamp, 20.5)
    assert record.source_port == 80
    assert record.tcp_flags_syn is True


def test_numeric_operations() -> None:
    """Numeric operations should work without raising errors."""

    record = PcapRecord.from_parser_row({
        "frame_number": 1,
        "timestamp": 1.5,
        "source_port": 100,
    })
    assert record.frame_number + 1 == 2
    assert math.isclose(record.timestamp + 1.0, 2.5)
    assert record.source_port * 2 == 200

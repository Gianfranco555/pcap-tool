# tests/unit/core/test_pcaprecord_defaults.py

import pytest
import pandas as pd
from pcap_tool.core.models import PcapRecord
import math

class AttrDict(dict):
    """A dictionary that allows attribute-style access."""
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

def test_from_parser_row_handles_missing_fields():
    """Tests that the factory method provides defaults for missing fields."""
import types

def test_from_parser_row_handles_missing_fields():
    """Tests that the factory method provides defaults for missing fields."""
    row = types.SimpleNamespace()
    record = PcapRecord.from_parser_row(row)
    assert record.frame_number == 0
    assert record.source_ip == ""
    assert record.packet_length == 0
    assert record.ip_flags_df is False

def test_from_parser_row_handles_none_and_nan():
    """Tests that None and NaN are converted to their defaults."""
    row = AttrDict({
        "frame_number": None,
        "source_port": pd.NA,
        "ip_ttl": float('nan'),
        "protocol": None,
    })
    record = PcapRecord.from_parser_row(row)
    assert record.frame_number == 0
    assert record.source_port == 0
    assert record.ip_ttl == 0
    assert record.protocol == ""

def test_from_parser_row_coerces_types():
    """Tests that string representations of numbers are coerced."""
    row = AttrDict({
        "frame_number": "123",
        "timestamp": "123.456",
        "source_port": "8080",
        "ip_flags_df": "True",
    })
    record = PcapRecord.from_parser_row(row)
    assert record.frame_number == 123
    assert record.timestamp == 123.456
    assert record.source_port == 8080
    assert record.ip_flags_df is True

def test_successful_numeric_operations():
    """Ensures that fields are numeric and can be used in operations."""
    row = AttrDict({"packet_length": "1500", "ip_ttl": "64"})
    record = PcapRecord.from_parser_row(row)
    # This will raise a TypeError if the fields are not numbers
    result = record.packet_length - record.ip_ttl
    assert result == 1436

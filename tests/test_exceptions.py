"""Tests for custom exception hierarchy."""

import pytest

from pcap_tool.exceptions import (
    PcapToolError,
    PcapParsingError,
    CorruptPcapError,
    RuleFileError,
    RuleLogicError,
    ReportGenerationError,
    AISummaryError,
    AnalysisError,
)


def test_exceptions_can_be_caught():
    """Each custom exception should be catchable via the base class."""
    with pytest.raises(PcapToolError):
        raise PcapToolError()
    for exc_cls in [
        PcapParsingError,
        CorruptPcapError,
        RuleFileError,
        RuleLogicError,
        ReportGenerationError,
        AISummaryError,
        AnalysisError,
    ]:
        with pytest.raises(PcapToolError):
            raise exc_cls()


def test_corrupt_pcap_is_subclass():
    """CorruptPcapError must inherit from PcapParsingError."""
    assert issubclass(CorruptPcapError, PcapParsingError)

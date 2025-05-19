"""Custom exceptions for pcap_tool package."""

class PcapToolError(Exception):
    """Base class for all custom pcap_tool exceptions."""


class PcapParsingError(PcapToolError):
    """Raised when parsing of a pcap file fails."""


class CorruptPcapError(PcapParsingError):
    """Raised when the pcap file is corrupt or has an invalid format."""


class RuleFileError(PcapToolError):
    """Raised when there is an issue loading or parsing the rules.yaml file."""


class RuleLogicError(PcapToolError):
    """Raised when an error occurs during heuristic rule evaluation."""


class ReportGenerationError(PcapToolError):
    """Raised when PDF or other report generation fails."""


class AISummaryError(PcapToolError):
    """Raised when AI summary generation fails."""

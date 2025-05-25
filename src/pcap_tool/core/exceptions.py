"""Custom exceptions for the :mod:`pcap_tool` package."""


class PcapToolError(Exception):
    """Base class for all custom ``pcap_tool`` exceptions.

    Parameters
    ----------
    message:
        Short description of the failure.
    context:
        Optional additional information about where/why the error occurred.
    suggestion:
        Optional hint that may help recover from the error.
    """

    def __init__(
        self,
        message: str = "",
        *,
        context: str | None = None,
        suggestion: str | None = None,
    ) -> None:
        super().__init__(message)
        self.context = context
        self.suggestion = suggestion


class PcapParsingError(PcapToolError):
    """Raised when parsing of a PCAP file fails."""


class CorruptPcapError(PcapParsingError):
    """Raised when the PCAP file is corrupt or has an invalid format."""


class RuleFileError(PcapToolError):
    """Raised when there is an issue loading or parsing the ``rules.yaml`` file."""


class RuleLogicError(PcapToolError):
    """Raised when an error occurs during heuristic rule evaluation."""


class ReportGenerationError(PcapToolError):
    """Raised when PDF or other report generation fails."""


class AISummaryError(PcapToolError):
    """Raised when AI summary generation fails."""


class ParserNotAvailable(PcapToolError):
    """Raised when no parser backend is available."""


class AnalysisError(PcapToolError):
    """Raised when a data analysis step fails."""

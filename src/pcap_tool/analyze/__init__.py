import warnings

from ..analysis import ErrorSummarizer, PerformanceAnalyzer, SecurityAuditor

warnings.warn(
    "The 'pcap_tool.analyze' module is deprecated and will be removed in a future version. "
    "Please use 'pcap_tool.analysis' instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "ErrorSummarizer",
    "PerformanceAnalyzer",
    "SecurityAuditor",
]

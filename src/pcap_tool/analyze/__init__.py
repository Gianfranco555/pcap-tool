import warnings

from ..analysis.errors import ErrorSummarizer
from ..analysis.performance import PerformanceAnalyzer
from ..analysis.security import SecurityAuditor

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

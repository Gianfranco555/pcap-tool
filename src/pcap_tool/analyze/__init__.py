"""Deprecated analyze namespace.

Use :mod:`pcap_tool.analysis` instead. This module re-exports from
:mod:`pcap_tool.analysis.legacy` for backward compatibility and emits a
:class:`DeprecationWarning`.
"""

import sys
import warnings

from ..analysis import legacy as _legacy

warnings.warn(
    "pcap_tool.analyze is deprecated; use pcap_tool.analysis instead.",
    DeprecationWarning,
    stacklevel=2,
)

ErrorSummarizer = _legacy.ErrorSummarizer
PerformanceAnalyzer = _legacy.PerformanceAnalyzer
SecurityAuditor = _legacy.SecurityAuditor

# Expose legacy submodules for direct imports
sys.modules[__name__ + ".error_summarizer"] = _legacy.error_summarizer
sys.modules[__name__ + ".performance_analyzer"] = _legacy.performance_analyzer
sys.modules[__name__ + ".security_auditor"] = _legacy.security_auditor

__all__ = ["ErrorSummarizer", "PerformanceAnalyzer", "SecurityAuditor"]

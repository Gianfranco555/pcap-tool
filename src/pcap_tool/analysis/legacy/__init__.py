"""Compatibility wrappers for deprecated :mod:`pcap_tool.analyze` modules.

These shims import the canonical implementations from
:mod:`pcap_tool.analysis`.  New code should import from the ``analysis``
package directly.
"""

from . import error_summarizer, performance_analyzer, security_auditor
from .error_summarizer import ErrorSummarizer
from .performance_analyzer import PerformanceAnalyzer
from .security_auditor import SecurityAuditor

__all__ = ["ErrorSummarizer", "PerformanceAnalyzer", "SecurityAuditor"]

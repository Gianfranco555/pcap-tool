import warnings
import pytest

from pcap_tool import analyze
from pcap_tool.analysis import errors, performance, security

def test_shim_imports_and_references_are_identical():
    """
    Verify that importing from the deprecated path and the canonical path
    results in identical objects and that a DeprecationWarning is issued.
    """
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        # Import from the deprecated path
        from pcap_tool import analyze as deprecated_analyze

        # Check if a DeprecationWarning was issued
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "pcap_tool.analyze' module is deprecated" in str(w[-1].message)

        # Assert that the objects are identical
        assert deprecated_analyze.ErrorSummarizer is errors.ErrorSummarizer
        assert deprecated_analyze.PerformanceAnalyzer is performance.PerformanceAnalyzer
        assert deprecated_analyze.SecurityAuditor is security.SecurityAuditor

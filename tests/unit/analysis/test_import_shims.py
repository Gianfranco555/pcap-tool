import importlib


def test_analyze_and_legacy_identical():
    import pcap_tool.analyze as analyze
    import pcap_tool.analysis.legacy as legacy
    from pcap_tool.analysis import (
        PerformanceAnalyzer,
        ErrorSummarizer,
        SecurityAuditor,
    )

    assert analyze.PerformanceAnalyzer is legacy.PerformanceAnalyzer is PerformanceAnalyzer
    assert analyze.ErrorSummarizer is legacy.ErrorSummarizer is ErrorSummarizer
    assert analyze.SecurityAuditor is legacy.SecurityAuditor is SecurityAuditor

    from pcap_tool.analyze.performance_analyzer import PerformanceAnalyzer as A_PA
    from pcap_tool.analysis.legacy.performance_analyzer import PerformanceAnalyzer as L_PA
    assert A_PA is L_PA is PerformanceAnalyzer

    from pcap_tool.analyze.error_summarizer import ErrorSummarizer as A_ES
    from pcap_tool.analysis.legacy.error_summarizer import ErrorSummarizer as L_ES
    assert A_ES is L_ES is ErrorSummarizer

    from pcap_tool.analyze.security_auditor import SecurityAuditor as A_SA
    from pcap_tool.analysis.legacy.security_auditor import SecurityAuditor as L_SA
    assert A_SA is L_SA is SecurityAuditor

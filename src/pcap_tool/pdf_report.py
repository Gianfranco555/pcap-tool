"""Public PDF report API re-exported for convenience."""

from .reporting import pdf_report as _pdf_report

# Expose the element-building helper so tests can monkeypatch it
_build_elements = _pdf_report._build_elements


def generate_pdf_report(*args, **kwargs):
    """Proxy to :func:`pcap_tool.reporting.pdf_report.generate_pdf_report`.

    The helper ``_build_elements`` is looked up from this module so tests that
    patch ``pcap_tool.pdf_report._build_elements`` affect the behaviour.
    """

    original = _pdf_report._build_elements
    _pdf_report._build_elements = _build_elements
    try:
        return _pdf_report.generate_pdf_report(*args, **kwargs)
    finally:
        _pdf_report._build_elements = original


__all__ = ["generate_pdf_report", "_build_elements"]

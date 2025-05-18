import pandas as pd
import pytest

from pcap_tool.pdf_report import generate_pdf_report


def test_generate_pdf_report_basic():
    df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
    try:
        pdf_bytes = generate_pdf_report(df)
    except ImportError:
        pytest.skip("ReportLab not installed")
    assert isinstance(pdf_bytes, (bytes, bytearray))
    assert len(pdf_bytes) > 0

import pandas as pd
import pytest
from io import BytesIO

from pcap_tool.summary import export_summary_excel


def test_export_summary_excel_basic():
    df = pd.DataFrame({
        'protocol': ['TCP', 'UDP', 'TCP'],
        'src_ip': ['1.1.1.1', '2.2.2.2', '1.1.1.1'],
    })
    buffer = BytesIO()
    try:
        export_summary_excel(df, buffer)
    except ImportError:
        pytest.skip("Excel writer not installed")
    buffer.seek(0)
    excel = pd.ExcelFile(buffer)
    assert set(excel.sheet_names) == {'TCP', 'UDP'}

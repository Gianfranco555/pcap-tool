import pytest

from pcap_tool.pdf_report import generate_pdf_report, _build_elements, _select_top_flows
from pcap_tool.exceptions import ReportGenerationError


def test_generate_pdf_report_basic():
    metrics = {
        "capture_info": {"filename": "test.pcap"},
        "protocols": {"tcp": 1, "udp": 1},
        "top_ports": {"tcp_80": 1},
        "top_talkers_by_bytes": [
            {"src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "bytes_total": 1000}
        ],
        "performance_metrics": {"median_rtt_ms": 10, "retrans_pct": 0.0},
        "error_summary": {},
        "security_findings": {},
        "timeline_data": [],
    }
    try:
        pdf_bytes = generate_pdf_report(metrics)
    except ImportError:
        pytest.skip("ReportLab not installed")
    assert isinstance(pdf_bytes, (bytes, bytearray))
    assert len(pdf_bytes) > 0


def test_generate_pdf_report_error(monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr("pcap_tool.pdf_report._build_elements", boom)

    with pytest.raises(ReportGenerationError):
        generate_pdf_report({})


def test_capture_summary_section():
    metrics = {
        "capture_info": {
            "filename": "summary.pcap",
            "file_size": 1024,
            "total_packets": 5,
            "capture_duration": 1.2,
        }
    }
    try:
        from reportlab.lib.styles import getSampleStyleSheet
    except Exception:
        pytest.skip("ReportLab not installed")

    styles = getSampleStyleSheet()
    elements = _build_elements(metrics, None, styles, None)
    texts = [e.text for e in elements if hasattr(e, "text")]
    assert "Capture Summary" in texts
    assert any("Filename" in t for t in texts)


def test_ai_summary_section():
    try:
        from reportlab.lib.styles import getSampleStyleSheet
    except Exception:
        pytest.skip("ReportLab not installed")

    styles = getSampleStyleSheet()
    elements = _build_elements({}, None, styles, "This is the summary")
    texts = [e.text for e in elements if hasattr(e, "text")]
    assert "AI-Generated Summary" in texts
    assert any("This is the summary" in t for t in texts)


def test_select_top_flows_scoring():
    import pandas as pd

    df = pd.DataFrame(
        [
            {"flow_disposition": "Allowed", "bytes_total": 1000, "security_observation": "None"},
            {"flow_disposition": "Blocked - Test", "bytes_total": 10, "security_observation": "alert"},
            {"flow_disposition": "Degraded", "bytes_total": 20, "security_observation": "None"},
        ]
    )

    result = _select_top_flows(df, count=3)
    assert result.iloc[0]["flow_disposition"].startswith("Blocked")
    assert result.iloc[1]["flow_disposition"] == "Degraded"

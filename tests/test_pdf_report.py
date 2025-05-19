import pytest

from pcap_tool.pdf_report import generate_pdf_report


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

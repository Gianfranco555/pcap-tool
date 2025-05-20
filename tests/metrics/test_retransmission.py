from pcap_tool.metrics.retransmission import categorize_retransmission_severity


def test_retransmission_severity_categories():
    assert categorize_retransmission_severity(0.5) == {
        "status": "Healthy",
        "color": "#28a745",
    }
    assert categorize_retransmission_severity(1.5) == {
        "status": "Warning",
        "color": "#ffc107",
    }
    assert categorize_retransmission_severity(5.0) == {
        "status": "Critical",
        "color": "#dc3545",
    }

import pandas as pd

from pcap_tool.analysis.errors.error_summarizer import ErrorSummarizer


def test_summarize_errors_basic():
    df = pd.DataFrame(
        {
            "flow_id": ["f1", "f2", "f3", "f4"],
            "flow_error_type": [
                "TCP_RESET",
                "TCP_RESET",
                "TLS_FATAL_HANDSHAKE_FAILURE",
                "ICMP_DEST_UNREACHABLE_HOST",
            ],
            "flow_error_details": [
                "src1",
                "src2",
                "handshake_failure",
                "host_unreachable",
            ],
        }
    )

    result = ErrorSummarizer().summarize_errors(df)
    assert result["TCP_RESET"]["src1"]["count"] == 1
    assert "f1" in result["TCP_RESET"]["src1"]["sample_flow_ids"]
    assert result["TLS_FATAL_HANDSHAKE_FAILURE"]["handshake_failure"]["count"] == 1
    assert result["ICMP_DEST_UNREACHABLE_HOST"]["host_unreachable"]["count"] == 1

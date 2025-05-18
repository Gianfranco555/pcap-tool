from pathlib import Path
import pytest

from pcap_tool.parser import parse_pcap_to_df, parse_pcap

FIXTURES = Path(__file__).with_suffix('').parent / "fixtures"


def _load_df(pcap_path: Path):
    try:
        return parse_pcap_to_df(str(pcap_path), workers=0)
    except Exception:
        return parse_pcap(str(pcap_path)).as_dataframe()


def _has_token(df, column: str, token: str) -> bool:
    return any(token in (vals or []) for vals in df[column])


@pytest.mark.parametrize(
    "pcap_file,expect",
    [
        (
            "client-fast-retrans.pcap",
            lambda df: any(
                "fast_retransmission" in (row["tcp_analysis_retransmission_flags"] or [])
                and row.get("dup_ack_num") == 3
                for _, row in df.iterrows()
            ),
        ),
        (
            "zero_window_probe.pcapng",
            lambda df: any(
                "zero_window" in (flags := (row["tcp_analysis_window_flags"] or []))
                and "zero_window_probe" in flags
                for _, row in df.iterrows()
            ),
        ),
    ],
)
def test_tcp_analysis_flags(pcap_file, expect):
    pcap_path = FIXTURES / pcap_file
    df = _load_df(pcap_path)
    assert not df.empty
    assert expect(df)

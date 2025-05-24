import pandas as pd
from pcap_tool.performance import count_plaintext_http_flows_df


def test_plaintext_detection_from_failure_csv():
    df = pd.read_csv('tests/fixtures/Failure_Pcap.csv')
    count = count_plaintext_http_flows_df(df)
    assert count == 2  # Expecting 2 plaintext flows in Failure_Pcap.csv

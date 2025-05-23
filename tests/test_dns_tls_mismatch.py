import pandas as pd
from pcap_tool.heuristics.dns_tls_mismatch import detect_dns_sni_mismatch


def test_detect_dns_sni_mismatch_basic():
    ts_dns = pd.Timestamp('2023-01-01 00:00:00')
    ts_tls_ok = ts_dns + pd.Timedelta(seconds=30)
    ts_tls_bad = ts_dns + pd.Timedelta(seconds=50)
    df = pd.DataFrame([
        {
            "flow_id": 1,
            "src_ip": "1.1.1.1",
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "dns_query_name": "example.com",
            "dns_response_addresses": ["2.2.2.2"],
            "timestamp": ts_dns,
        },
        {
            "flow_id": 2,
            "src_ip": "1.1.1.1",
            "dest_ip": "2.2.2.2",
            "dest_port": 443,
            "server_name_indication": "example.com",
            "timestamp": ts_tls_ok,
        },
        {
            "flow_id": 3,
            "src_ip": "1.1.1.1",
            "dest_ip": "3.3.3.3",
            "dest_port": 443,
            "server_name_indication": "example.com",
            "timestamp": ts_tls_bad,
        },
    ])

    result = detect_dns_sni_mismatch(df)
    assert list(result["flow_id"]) == [3]
    assert result.iloc[0]["flow_disposition"] == "Mis-routed"

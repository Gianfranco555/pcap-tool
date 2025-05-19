import pandas as pd
from pcap_tool.summary import generate_summary_df


def test_generate_summary_df_basic():
    timestamps = pd.to_datetime([
        "2023-01-01 00:00:01",
        "2023-01-01 00:00:02",
        "2023-01-01 00:00:03",
        "2023-01-01 00:00:04",
    ])
    data = {
        "timestamp": timestamps,
        "source_ip": ["1.1.1.1", "2.2.2.2", "1.1.1.1", "2.2.2.2"],
        "destination_ip": ["2.2.2.2", "1.1.1.1", "2.2.2.2", "1.1.1.1"],
        "source_port": [1111, 80, 1111, 80],
        "destination_port": [80, 1111, 80, 1111],
        "protocol": ["TCP", "TCP", "TCP", "TCP"],
        "packet_length": [10, 20, 30, 40],
        "is_src_client": [True, False, True, False],
        "flow_disposition": ["Allowed", "Blocked", "Allowed", "Blocked"],
        "traffic_type_guess": ["HTTP", "HTTP", "DNS", "HTTP"],
        "security_observation": ["obs1", "obs2", "obs1", "obs2"],
        "sni": [None, None, None, None],
        "http_request_host_header": ["example.com", None, None, None],
        "http_request_uri": ["/index", None, None, None],
        "dns_query_name": ["example.com"] * 4,
        "dns_response_code": ["NOERROR"] * 4,
        "dns_response_addresses": [["2.2.2.2"]] * 4,
    }
    df = pd.DataFrame(data)

    summary = generate_summary_df(df)
    assert len(summary) == 1
    row = summary.iloc[0]
    assert row["src_ip"] == "1.1.1.1"
    assert row["dest_ip"] == "2.2.2.2"
    assert row["pkts_total"] == 4
    assert row["flow_disposition"] == "Blocked"
    assert row["primary_traffic_type_guess"] == "HTTP"
    assert row["security_observations"] == "obs1;obs2"
    assert row["dns_query"] == "example.com"


def test_generate_summary_df_missing_is_src_client(caplog):
    timestamps = pd.to_datetime([
        "2023-01-01 00:00:01",
        "2023-01-01 00:00:02",
        "2023-01-01 00:00:03",
        "2023-01-01 00:00:04",
    ])
    data = {
        "timestamp": timestamps,
        "source_ip": ["1.1.1.1", "2.2.2.2", "1.1.1.1", "2.2.2.2"],
        "destination_ip": ["2.2.2.2", "1.1.1.1", "2.2.2.2", "1.1.1.1"],
        "source_port": [1111, 80, 1111, 80],
        "destination_port": [80, 1111, 80, 1111],
        "protocol": ["TCP", "TCP", "TCP", "TCP"],
        "packet_length": [10, 20, 30, 40],
        "flow_disposition": ["Allowed", "Blocked", "Allowed", "Blocked"],
        "traffic_type_guess": ["HTTP", "HTTP", "DNS", "HTTP"],
        "security_observation": ["obs1", "obs2", "obs1", "obs2"],
        "sni": [None, None, None, None],
        "http_request_host_header": ["example.com", None, None, None],
        "http_request_uri": ["/index", None, None, None],
        "dns_query_name": ["example.com"] * 4,
        "dns_response_code": ["NOERROR"] * 4,
        "dns_response_addresses": [["2.2.2.2"]] * 4,
    }
    df = pd.DataFrame(data)

    with caplog.at_level("WARNING"):
        summary = generate_summary_df(df)

    assert "is_src_client" in caplog.text
    assert len(summary) == 2
    assert summary.pkts_total.sum() == 4
    assert summary.pkts_c2s.sum() == 0
    assert summary.pkts_s2c.sum() == 4

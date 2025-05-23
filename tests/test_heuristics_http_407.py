import pandas as pd
from pcap_tool.heuristics.engine import VectorisedHeuristicEngine


def test_http_407_tagging():
    df = pd.DataFrame({
        "proto": ["HTTP", "HTTP"],
        "http_status": [407, 200],
    })
    engine = VectorisedHeuristicEngine()
    result = engine._apply_rules(df)

    assert result.loc[0, "flow_disposition"] == "Blocked"
    assert result.loc[0, "flow_cause"] == "Proxy Authentication Failed"
    assert result.loc[1, "flow_disposition"] == "Unknown"
    assert result.loc[1, "flow_cause"] == "Undetermined"

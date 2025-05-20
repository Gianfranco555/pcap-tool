import pandas as pd

from pcap_tool.ai import prepare_ai_data


def test_prepare_ai_data_empty():
    result = prepare_ai_data(pd.DataFrame())
    assert result == {"capture_info": {}, "flows": []}

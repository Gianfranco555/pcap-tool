from pathlib import Path
from pcap_tool.parser import parse_pcap_to_df

def test_mini_fixture():
    df = parse_pcap_to_df(Path(__file__).parent / "../fixtures/mini.pcapng")
    assert not df.empty

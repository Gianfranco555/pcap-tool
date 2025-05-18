import pandas as pd
from pcap_tool.parser import iter_parsed_frames


def test_iter_frames_chunking(example_pcap):
    chunks = list(iter_parsed_frames(example_pcap, chunk_size=5))
    assert len(chunks) >= 2
    assert all(df.shape[0] <= 5 for df in chunks)

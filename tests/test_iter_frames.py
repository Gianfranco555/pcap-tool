import pandas as pd
from pcap_tool.parser import iter_parsed_frames


def test_iter_frames_chunking(example_pcap):
    chunks = list(iter_parsed_frames(example_pcap, chunk_size=5))
    assert len(chunks) >= 2
    assert all(df.shape[0] <= 5 for df in chunks)


def test_multiprocessing_order(example_pcap):
    single = list(iter_parsed_frames(example_pcap, chunk_size=2, workers=0))
    numbers_single = [n for df in single for n in df["frame_number"].tolist()]

    multi = list(iter_parsed_frames(example_pcap, chunk_size=2, workers=2))
    numbers_multi = [n for df in multi for n in df["frame_number"].tolist()]

    assert numbers_multi == numbers_single

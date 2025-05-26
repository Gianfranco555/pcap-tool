import time
import numpy as np
import pandas as pd
from pcap_tool.analysis.performance.performance_analyzer import PerformanceAnalyzer


def test_collect_rtt_samples_perf():
    n = 1000
    df = pd.DataFrame({
        "protocol": ["TCP"] * n,
        "tcp_flags_syn": [True, True] * (n // 2),
        "tcp_flags_ack": [False, True] * (n // 2),
        "source_ip": ["1.1.1.1"] * (n // 2) + ["2.2.2.2"] * (n // 2),
        "destination_ip": ["2.2.2.2"] * (n // 2) + ["1.1.1.1"] * (n // 2),
        "source_port": [1234] * (n // 2) + [80] * (n // 2),
        "destination_port": [80] * (n // 2) + [1234] * (n // 2),
        "timestamp": np.arange(n) / 1000.0,
    })
    start = time.perf_counter()
    samples = PerformanceAnalyzer.collect_rtt_samples(df)
    duration = time.perf_counter() - start
    assert samples
    assert duration < 1.0

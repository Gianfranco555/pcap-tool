# Performance Notes

This project processes PCAP files using pandas DataFrames and can be CPU intensive on large captures. The following practices help keep runtime reasonable:

* Packet parsing uses Python multiprocessing when more than one worker is requested.
* Critical numeric calculations rely on `numpy` functions for speed.
* `PerformanceAnalyzer.collect_rtt_samples` now uses vectorised pandas operations rather than per-row loops.

There is currently no database component, so connection pooling and batched queries are not applicable.

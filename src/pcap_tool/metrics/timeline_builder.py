"""Timeline metrics utilities."""

from collections import defaultdict
from statistics import mean, pstdev
from typing import DefaultDict, List

from ..parser import PcapRecord


class TimelineBuilder:
    """Aggregate per-second packet and byte counts."""

    def __init__(self) -> None:
        self.bytes_per_second: DefaultDict[int, int] = defaultdict(int)
        self.packets_per_second: DefaultDict[int, int] = defaultdict(int)

    def add_packet(self, record: PcapRecord) -> None:
        """Add a packet record to the timeline."""
        sec_bin = int(record.timestamp)
        self.bytes_per_second[sec_bin] += record.packet_length or 0
        self.packets_per_second[sec_bin] += 1

    def get_timeline_data(self) -> tuple[list[int], list[int], list[int]]:
        """Return sorted time bins and corresponding byte/packet counts."""
        bins = set(self.bytes_per_second.keys()) | set(self.packets_per_second.keys())
        sorted_bins = sorted(bins)
        bytes_list = [self.bytes_per_second.get(b, 0) for b in sorted_bins]
        packets_list = [self.packets_per_second.get(b, 0) for b in sorted_bins]
        return sorted_bins, bytes_list, packets_list

    def find_spikes(self, values: List[int], sigma: float = 3.0) -> List[int]:
        """Return indices where ``value`` is greater than ``mean + sigma * std``."""
        if not values:
            return []
        if len(set(values)) <= 1:
            return []
        avg = mean(values)
        std_dev = pstdev(values)
        if std_dev == 0:
            return []
        threshold = avg + sigma * std_dev
        return [i for i, v in enumerate(values) if v > threshold]

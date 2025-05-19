from pcap_tool.metrics.timeline_builder import TimelineBuilder
from pcap_tool.models import PcapRecord


def test_timeline_builder_basic():
    tb = TimelineBuilder()
    records = [
        PcapRecord(frame_number=1, timestamp=1.2, packet_length=100),
        PcapRecord(frame_number=2, timestamp=1.8, packet_length=200),
        PcapRecord(frame_number=3, timestamp=2.4, packet_length=50),
    ]
    for r in records:
        tb.add_packet(r)

    bins, bytes_list, pkts_list = tb.get_timeline_data()
    assert bins == [1, 2]
    assert bytes_list == [300, 50]
    assert pkts_list == [2, 1]


def test_timeline_builder_find_spikes():
    tb = TimelineBuilder()
    values = [10, 12, 11, 100, 9]
    spikes = tb.find_spikes(values, sigma=1.0)
    assert spikes == [3]
    assert tb.find_spikes([5, 5, 5]) == []
    assert tb.find_spikes([]) == []

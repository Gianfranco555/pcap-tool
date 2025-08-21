from __future__ import annotations

from typing import Iterator

from pcap_tool.core.models import PcapRecord
from pcap_tool.parsers.factory import ParserFactory


def iter_parsed_frames(path: str) -> Iterator[PcapRecord]:
    """
    Lazily iterates through a PCAP file and yields PcapRecord objects for each frame.

    This function uses a streaming approach to avoid loading the entire file into memory,
    making it suitable for very large PCAP files. Memory usage should be O(1) with
    respect to the number of packets.

    Args:
        path: The file path to the PCAP file.

    Yields:
        PcapRecord: A parsed record for each frame in the file.
    """
    parser = ParserFactory.create_parser()
    yield from parser.parse(path, max_packets=None)

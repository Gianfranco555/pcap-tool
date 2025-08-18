from collections.abc import Iterator

from pcap_tool.core.models import PcapRecord
from pcap_tool.orchestrator.ingestor import iter_parsed_frames
from pcap_tool.parsers.factory import ParserFactory


class DummyParser:
    """Parser yielding a large number of lightweight rows lazily."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.generated = 0

    @classmethod
    def validate(cls) -> bool:  # pragma: no cover - not used directly
        return True

    def parse(self, _file_path: str, *, max_packets=None, _start: int = 0, _slice_size=None):
        for i in range(self.count):
            self.generated += 1
            yield {"frame_number": i}


def test_iter_parsed_frames_streams_lazily(monkeypatch):
    """Ensure records are produced lazily with constant memory."""

    dummy = DummyParser(1_000_001)
    monkeypatch.setattr(ParserFactory, "create_parser", lambda preferred=None: dummy)

    gen = iter_parsed_frames("dummy.pcap")
    assert isinstance(gen, Iterator)
    assert dummy.generated == 0

    # Consume a handful of records to verify streaming behaviour
    first = next(gen)
    assert isinstance(first, PcapRecord)
    assert first.frame_number == 0
    assert dummy.generated == 1

    # Iterate over additional records without materialising the whole source
    for i, rec in zip(range(1, 1000), gen):
        assert rec.frame_number == i
    assert dummy.generated == 1000  # only the consumed rows were generated
    assert dummy.generated < dummy.count

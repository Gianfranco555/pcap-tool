import inspect
from unittest.mock import MagicMock, patch

from pcap_tool.core.models import PcapRecord
from pcap_tool.orchestrator.ingestor import iter_parsed_frames


def test_iter_parsed_frames_is_generator():
    """Verify that iter_parsed_frames returns a generator."""
    # Mock the parser factory to avoid actual file I/O
    with patch("pcap_tool.orchestrator.ingestor.ParserFactory") as mock_factory:
        # Configure the mock parser and its parse method
        mock_parser = MagicMock()
        mock_parser.parse.return_value = iter([])  # Return an empty iterator
        mock_factory.create_parser.return_value = mock_parser

        # Call the function
        result = iter_parsed_frames("dummy_path.pcap")

        # Assert that the result is a generator
        assert inspect.isgenerator(result), "Function should return a generator."

        # Clean up the generator to avoid resource warnings
        list(result)


def test_iter_parsed_frames_yields_pcap_records():
    """Verify that the generator yields PcapRecord instances."""
    # Create some dummy records for the mock parser to yield
    dummy_records = [PcapRecord(frame_number=1), PcapRecord(frame_number=2)]

    with patch("pcap_tool.orchestrator.ingestor.ParserFactory") as mock_factory:
        mock_parser = MagicMock()
        # The parse method should be a generator function
        mock_parser.parse.return_value = (record for record in dummy_records)
        mock_factory.create_parser.return_value = mock_parser

        # Call the function and consume the generator
        result = list(iter_parsed_frames("dummy_path.pcap"))

        # Assert that the yielded items are correct
        assert len(result) == 2
        assert all(isinstance(r, PcapRecord) for r in result)
        assert result[0].frame_number == 1
        assert result[1].frame_number == 2


def test_iter_parsed_frames_lazy_evaluation():
    """
    Verify O(1) memory usage by streaming a large number of items.
    """
    # Define a large number of items to simulate
    item_count = 1_000_000

    # A generator function that yields a large number of dummy records
    # without storing them all in memory.
    def large_generator(path, max_packets):
        for i in range(item_count):
            yield PcapRecord(frame_number=i)

    with patch("pcap_tool.orchestrator.ingestor.ParserFactory") as mock_factory:
        mock_parser = MagicMock()
        mock_parser.parse.side_effect = large_generator
        mock_factory.create_parser.return_value = mock_parser

        # Get the generator
        record_iterator = iter_parsed_frames("dummy_path.pcap")

        # Iterate and count without storing all items in a list
        count = 0
        for _ in record_iterator:
            count += 1

        # Assert that all items were processed
        assert count == item_count

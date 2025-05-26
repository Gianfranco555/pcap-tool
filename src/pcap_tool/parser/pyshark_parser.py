from typing import Generator, Optional

from ..core.models import PcapRecord

from ..parsers.pyshark_parser import PySharkParser, USE_PYSHARK


def _parse_with_pyshark(
    file_path: str,
    max_packets: Optional[int],
    *,
    start: int = 0,
    slice_size: Optional[int] = None,
) -> Generator[PcapRecord, None, None]:
    """Backwards compatible wrapper around :class:`PySharkParser`."""

    parser = PySharkParser()
    yield from parser.parse(
        file_path,
        max_packets,
        start=start,
        slice_size=slice_size,
    )


__all__ = ["_parse_with_pyshark", "USE_PYSHARK"]

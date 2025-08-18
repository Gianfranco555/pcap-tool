"""Streaming ingestion helpers.

This module exposes :func:`iter_parsed_frames` which provides a very light
interface around the parser ``Factory``.  The existing parsers expose a
``parse`` generator that yields raw dictionaries describing each packet.  The
previous implementation in the project materialised those dictionaries into a
``pandas`` ``DataFrame`` which required loading every packet into memory.  For
large captures this approach was prohibitive.

The function below replaces that behaviour with a streaming generator of
``PcapRecord`` objects.  Each row produced by the parser is converted on the
fly using :meth:`pcap_tool.core.models.PcapRecord.from_parser_row` and yielded
immediately.  No intermediate list or ``DataFrame`` is built which keeps memory
usage at :math:`O(1)` with respect to the number of packets processed.
"""

from __future__ import annotations

from dataclasses import asdict
from collections.abc import Iterator

from ..core.models import PcapRecord
from ..parsers.factory import ParserFactory


def iter_parsed_frames(path: str) -> Iterator[PcapRecord]:
    """Yield :class:`PcapRecord` objects for packets contained in ``path``.

    The appropriate parser backend is obtained from
    :class:`pcap_tool.parsers.factory.ParserFactory`.  The backend returns an
    iterator of *rows* (typically dictionaries) which are converted to
    ``PcapRecord`` instances lazily.  Items are yielded as soon as they are
    produced so the function's memory footprint remains constant regardless of
    the size of the source PCAP.
    """

    parser = ParserFactory.create_parser()
    for row in parser.parse(path, max_packets=None):
        # ``row`` may already be a ``PcapRecord`` depending on the parser
        # implementation.  Normalise by converting to a dictionary before
        # feeding it into ``from_parser_row``.
        if isinstance(row, PcapRecord):  # pragma: no cover - defensive
            row_dict = asdict(row)
        else:
            row_dict = row
        yield PcapRecord.from_parser_row(row_dict)


__all__ = ["iter_parsed_frames"]

from __future__ import annotations

from typing import List

from .base import BaseParser
from .pyshark_parser import PysharkParser, USE_PYSHARK
from .pcapkit_parser import PcapkitParser, USE_PCAPKIT


class ParserFactory:
    """Return parser implementations in priority order."""

    @staticmethod
    def get_parsers() -> List[BaseParser]:
        parsers: List[BaseParser] = []
        if USE_PYSHARK and PysharkParser.validate():
            parsers.append(PysharkParser())
        if USE_PCAPKIT and PcapkitParser.validate():
            parsers.append(PcapkitParser())
        return parsers

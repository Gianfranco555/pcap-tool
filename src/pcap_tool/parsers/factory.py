from __future__ import annotations

from typing import List, Type, Optional

from pcap_tool.logging import get_logger
from ..core.exceptions import ParserNotAvailable
from .base import BaseParser
from .pyshark_parser import PysharkParser
from .pcapkit_parser import PcapkitParser

logger = get_logger(__name__)


class ParserFactory:
    """Factory for creating parser instances with preference handling."""

    _registry: List[Type[BaseParser]] = []

    @classmethod
    def register_parser(cls, parser_cls: Type[BaseParser], *, prefer: bool = False) -> None:
        """Register a parser class for selection."""
        if parser_cls in cls._registry:
            return
        if prefer:
            cls._registry.insert(0, parser_cls)
        else:
            cls._registry.append(parser_cls)
        logger.debug("Registered parser %s (prefer=%s)", parser_cls.__name__, prefer)

    @classmethod
    def available_parsers(cls) -> List[Type[BaseParser]]:
        """Return parser classes that validate successfully."""
        available: List[Type[BaseParser]] = []
        for parser_cls in cls._registry:
            try:
                if parser_cls.validate():
                    available.append(parser_cls)
            except Exception:  # pragma: no cover - defensive
                logger.debug("Validation check failed for %s", parser_cls.__name__)
        logger.debug("Available parsers: %s", [p.__name__ for p in available])
        return available

    @classmethod
    def create_parser(cls, preferred: Optional[str] = None) -> BaseParser:
        """Instantiate and return an available parser."""
        available = cls.available_parsers()
        if not available:
            logger.error("No parser backends are available")
            raise ParserNotAvailable(
                "No parser backend available. Install pyshark or pcapkit."
            )

        if preferred:
            for parser_cls in available:
                if parser_cls.__name__.lower().startswith(preferred.lower()):
                    logger.info("Using user preferred parser: %s", parser_cls.__name__)
                    return parser_cls()
            logger.warning(
                "Preferred parser '%s' not available, falling back to %s",
                preferred,
                available[0].__name__,
            )

        logger.info("Selected parser: %s", available[0].__name__)
        return available[0]()


# Register default parsers with PyShark preferred
ParserFactory.register_parser(PysharkParser, prefer=True)
ParserFactory.register_parser(PcapkitParser)

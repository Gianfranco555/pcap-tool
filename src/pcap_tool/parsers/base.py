from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generator, Optional

from ..core.models import PcapRecord


class BaseParser(ABC):
    """Abstract base class for parser implementations."""

    @classmethod
    @abstractmethod
    def validate(cls) -> bool:
        """Return ``True`` if the parser backend is available."""

    @abstractmethod
    def parse(
        self,
        file_path: str,
        max_packets: Optional[int],
        *,
        start: int = 0,
        slice_size: Optional[int] = None,
    ) -> Generator[PcapRecord, None, None]:
        """Yield :class:`PcapRecord` objects for ``file_path``."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional


class BaseProcessor(ABC):
    """Abstract base class for pipeline processors."""

    @abstractmethod
    def process(
        self, data: Any, *, on_progress: Optional[Callable[[int, Optional[int]], None]] = None
    ) -> Any:
        """Process ``data`` and return the result."""


class BaseAnalyzer(ABC):
    """Abstract base class for pipeline analyzers."""

    @abstractmethod
    def analyze(self, data: Any) -> Any:
        """Analyze ``data`` and return the result."""


class BaseReporter(ABC):
    """Abstract base class for pipeline reporters."""

    @abstractmethod
    def report(self, data: Any) -> Any:
        """Generate a report from ``data`` and return the result."""

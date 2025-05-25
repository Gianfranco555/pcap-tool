from __future__ import annotations

"""Lazy dependency container for optional packages."""

from importlib import import_module
from types import ModuleType
from typing import Dict, Optional

from pcap_tool.logging import get_logger


class DependencyContainer:
    """Manage optional third party dependencies."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._registry: Dict[str, str] = {}
        self._cache: Dict[str, Optional[ModuleType]] = {}

    def register(self, name: str, module_path: str) -> None:
        """Register an optional dependency."""
        self._registry[name] = module_path

    def _load(self, name: str) -> Optional[ModuleType]:
        if name in self._cache:
            return self._cache[name]
        module_path = self._registry.get(name)
        if module_path is None:
            raise KeyError(f"Unknown dependency: {name}")
        try:
            module = import_module(module_path)
        except (ImportError, ModuleNotFoundError):
            module = None
        except Exception as exc:  # pragma: no cover - runtime import check
            self.logger.warning(
                "Unexpected error loading optional dependency '%s' (%s): %s",
                name,
                module_path,
                exc,
            )
            module = None
        self._cache[name] = module
        return module

    def get(self, name: str) -> ModuleType:
        """Return the imported module or raise ``ImportError`` if missing."""
        module = self._load(name)
        if module is None:
            mod = self._registry.get(name, name)
            raise ImportError(
                f"Optional dependency '{mod}' is required for this feature"
            )
        return module

    def is_available(self, name: str) -> bool:
        """Return ``True`` if the dependency can be imported."""
        return self._load(name) is not None


# Global container with known optional dependencies
container = DependencyContainer()
container.register("pyshark", "pyshark")
container.register("pcapkit", "pcapkit")
container.register("geoip2", "geoip2")
container.register("reportlab", "reportlab")
container.register("openai", "openai")

__all__ = ["DependencyContainer", "container"]

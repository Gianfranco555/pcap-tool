from __future__ import annotations

from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
import json

import yaml

from .components import BaseAnalyzer, BaseProcessor, BaseReporter


@dataclass
class Pipeline:
    """Simple configurable pipeline for PCAP analysis."""

    processors: list[BaseProcessor] = field(default_factory=list)
    analyzers: list[BaseAnalyzer] = field(default_factory=list)
    reporters: list[BaseReporter] = field(default_factory=list)

    def add_processor(self, processor: BaseProcessor) -> None:
        """Add ``processor`` to the pipeline."""
        self.processors.append(processor)

    def add_analyzer(self, analyzer: BaseAnalyzer) -> None:
        """Add ``analyzer`` to the pipeline."""
        self.analyzers.append(analyzer)

    def add_reporter(self, reporter: BaseReporter) -> None:
        """Add ``reporter`` to the pipeline."""
        self.reporters.append(reporter)

    def _iter_components(self) -> Iterable[Any]:
        yield from self.processors
        yield from self.analyzers
        yield from self.reporters

    def run(self, data: Any, on_progress: Optional[Callable[[int, Optional[int]], None]] = None) -> Any:
        """Execute the pipeline with ``data``."""
        total_steps = len(self.processors) + len(self.analyzers) + len(self.reporters)
        step = 0
        for component in self._iter_components():
            step += 1
            if on_progress:
                on_progress(step, total_steps)
            if isinstance(component, BaseProcessor):
                data = component.process(data, on_progress=on_progress)
            elif isinstance(component, BaseAnalyzer):
                data = component.analyze(data)
            elif isinstance(component, BaseReporter):
                data = component.report(data)
        if on_progress:
            on_progress(total_steps, total_steps)
        return data

    @classmethod
    def from_config(cls, path: str | Path) -> "Pipeline":
        """Create a pipeline from a YAML or JSON configuration file."""
        config_path = Path(path)
        with config_path.open("r", encoding="utf-8") as fh:
            suffix = config_path.suffix.lower()
            if suffix in {".yaml", ".yml"}:
                config = yaml.safe_load(fh)
            elif suffix == ".json":
                config = json.load(fh)
            else:
                raise ValueError(
                    f"Unsupported configuration file format: '{config_path.suffix}'. "
                    "Supported formats are YAML (.yaml, .yml) and JSON (.json)."
                )

        pipeline = cls()
        for section, adder in (
            ("processors", pipeline.add_processor),
            ("analyzers", pipeline.add_analyzer),
            ("reporters", pipeline.add_reporter),
        ):
            for item in config.get(section, []):
                if isinstance(item, str):
                    obj = _load_object(item, {})
                else:
                    name = item.get("name")
                    if not isinstance(name, str) or not name:
                        raise ValueError(
                            f"Invalid or missing 'name' for component in section '{section}': {item}"
                        )
                    params = item.get("params", {})
                    obj = _load_object(name, params)
                adder(obj)
        return pipeline

def _load_object(path: str, params: dict) -> Any:
    module_name, _, attr = path.rpartition(".")
    try:
        module = import_module(module_name)
    except ModuleNotFoundError as e:
        raise ValueError(f"Failed to import module '{module_name}' for component '{path}': {e}") from e
    try:
        cls = getattr(module, attr)
    except AttributeError as e:
        raise ValueError(f"Failed to find class '{attr}' in module '{module_name}' for component '{path}': {e}") from e
    try:
        return cls(**params)
    except TypeError as e:
        raise ValueError(f"Failed to instantiate component '{path}' with params {params}: {e}") from e

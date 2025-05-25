"""Common decorators for error handling and performance logging."""

from __future__ import annotations

import time
import types
from functools import wraps

from ..logging import get_logger
from ..exceptions import PcapParsingError, AnalysisError, PcapToolError


logger = get_logger(__name__)


def _wrap_generator(gen, exc_cls, func_name):
    """Yield from ``gen`` while translating exceptions to ``exc_cls``."""
    try:
        for item in gen:
            yield item
    except exc_cls:
        raise
    except Exception as exc:  # pragma: no cover - runtime protection
        logger.error("%s failed: %s", func_name, exc, exc_info=True)
        raise exc_cls(str(exc)) from exc


def handle_parse_errors(func):
    """Wrap parser functions to raise :class:`PcapParsingError` on failure."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except PcapParsingError:
            raise
        except Exception as exc:  # pragma: no cover - runtime protection
            logger.error("Parsing error in %s: %s", func.__name__, exc, exc_info=True)
            raise PcapParsingError(str(exc)) from exc
        if isinstance(result, types.GeneratorType):
            return _wrap_generator(result, PcapParsingError, func.__name__)
        return result

    return wrapper


def handle_analysis_errors(func):
    """Wrap analysis methods to raise :class:`AnalysisError` on failure."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except AnalysisError:
            raise
        except Exception as exc:  # pragma: no cover - runtime protection
            logger.error("Analysis error in %s: %s", func.__name__, exc, exc_info=True)
            raise AnalysisError(str(exc)) from exc
        if isinstance(result, types.GeneratorType):
            return _wrap_generator(result, AnalysisError, func.__name__)
        return result

    return wrapper


def log_performance(func):
    """Log execution duration for ``func``."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
        except Exception:  # pragma: no cover - runtime protection
            duration = time.perf_counter() - start_time
            logger.info("%s call failed after %.3f seconds", func.__name__, duration)
            raise

        if isinstance(result, types.GeneratorType):
            def generator_wrapper():
                try:
                    for item in result:
                        yield item
                finally:
                    duration = time.perf_counter() - start_time
                    logger.info(
                        "%s (generator) iteration finished in %.3f seconds (total from initial call)",
                        func.__name__,
                        duration,
                    )

            return generator_wrapper()

        duration = time.perf_counter() - start_time
        logger.info("%s executed in %.3f seconds", func.__name__, duration)
        return result

    return wrapper

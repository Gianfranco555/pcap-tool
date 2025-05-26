from .reporting import pdf_report as _orig
from .reporting.pdf_report import *  # noqa: F401,F403


def __getattr__(name):  # pragma: no cover - module attribute proxy
    if name == "_build_elements":
        return _orig._build_elements
    raise AttributeError(name)


def __setattr__(name, value):  # pragma: no cover - module attribute proxy
    if name == "_build_elements":
        setattr(_orig, "_build_elements", value)
    globals()[name] = value

_build_elements = _orig._build_elements  # expose for direct import

__all__ = [
    name
    for name in globals().keys()
    if not name.startswith("_") or name == "_build_elements"
]


def generate_pdf_report(*args, **kwargs):
    """Wrapper that proxies to the real implementation using overridable helper."""
    old = _orig._build_elements
    _orig._build_elements = _build_elements
    try:
        return _orig.generate_pdf_report(*args, **kwargs)
    finally:
        _orig._build_elements = old

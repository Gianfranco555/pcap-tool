from __future__ import annotations

from functools import lru_cache
from typing import Any, Callable

from .models import PcapRecord

from .config import settings
from ..utils import safe_int_or_default


class FlowCache:
    """Cache helpers for flow calculations."""

    def __init__(self, maxsize: int | None = None, enabled: bool | None = None) -> None:
        self.enabled = settings.cache_enabled if enabled is None else enabled
        self.maxsize = maxsize if maxsize is not None else settings.flow_cache_size
        if self.enabled:
            self._derive_flow_id_cached = lru_cache(maxsize=self.maxsize)(self._derive_flow_id)
            self._flow_cache_key_cached = lru_cache(maxsize=self.maxsize)(self._flow_cache_key)
        else:
            self._derive_flow_id_cached = self._derive_flow_id
            self._flow_cache_key_cached = self._flow_cache_key

    # --- internal helper implementations ---
    def _derive_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> tuple[str, str, int, int, str]:
        return (src_ip, dst_ip, src_port, dst_port, proto)

    def _flow_cache_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
        stream_index: int | None,
        frame_number: int,
    ) -> str:
        if stream_index is not None:
            return f"TCP_STREAM_{stream_index}"
        if src_ip and dst_ip and proto:
            props = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            return f"{proto}_{props[0][0]}:{props[0][1]}_{props[1][0]}:{props[1][1]}"
        return f"UNKNOWN_FLOW_{frame_number}"

    # --- public API ---
    def derive_flow_id(self, rec: PcapRecord) -> tuple[str, str, int, int, str]:
        return self._derive_flow_id_cached(
            rec.source_ip or "",
            rec.destination_ip or "",
            safe_int_or_default(rec.source_port, 0),
            safe_int_or_default(rec.destination_port, 0),
            rec.protocol or "",
        )

    def flow_cache_key(self, rec: PcapRecord) -> str:
        return self._flow_cache_key_cached(
            rec.source_ip or "",
            rec.destination_ip or "",
            safe_int_or_default(rec.source_port, 0),
            safe_int_or_default(rec.destination_port, 0),
            rec.protocol or "",
            (lambda idx: None if idx == 0 else idx)(getattr(rec, "tcp_stream_index", None)),
            rec.frame_number,
        )

    def clear(self) -> None:
        if self.enabled:
            self._derive_flow_id_cached.cache_clear()  # type: ignore[attr-defined]
            self._flow_cache_key_cached.cache_clear()  # type: ignore[attr-defined]

    def stats(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        return {
            "derive_flow_id": self._derive_flow_id_cached.cache_info(),  # type: ignore[attr-defined]
            "flow_cache_key": self._flow_cache_key_cached.cache_info(),  # type: ignore[attr-defined]
        }


class PacketCache:
    """Generic cache for expensive packet computations."""

    def __init__(self, maxsize: int | None = None, enabled: bool | None = None) -> None:
        self.enabled = settings.cache_enabled if enabled is None else enabled
        self.maxsize = maxsize if maxsize is not None else settings.packet_cache_size
        self._cached_funcs: list[Callable[..., Any]] = []

    def memoize(self, func: Callable[..., Any]) -> Callable[..., Any]:
        if not self.enabled:
            return func
        cached = lru_cache(maxsize=self.maxsize)(func)
        self._cached_funcs.append(cached)
        return cached

    def clear(self) -> None:
        for f in self._cached_funcs:
            if hasattr(f, "cache_clear"):
                f.cache_clear()  # type: ignore[attr-defined]

    def stats(self) -> dict[str, Any]:
        return {f.__name__: f.cache_info() for f in self._cached_funcs if hasattr(f, "cache_info")}


__all__ = ["FlowCache", "PacketCache"]

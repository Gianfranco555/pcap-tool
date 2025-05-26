"""IP enrichment utilities."""

from __future__ import annotations

from pcap_tool.logging import get_logger
from ..core.config import settings
import socket
import sys
from typing import Any, Callable, Optional

from ..core.cache import PacketCache

geoip2: Any | None
Reader: Any | None
try:  # pragma: no cover - optional dependency
    from geoip2 import database as geoip2_database  # type: ignore
    from geoip2 import errors as geoip2_errors  # type: ignore

    geoip2 = sys.modules.get("geoip2")
    Reader = geoip2_database.Reader  # type: ignore
    AddressNotFoundError = geoip2_errors.AddressNotFoundError  # type: ignore
except Exception:  # pragma: no cover - optional dependency missing
    geoip2 = None
    Reader = None
    class AddressNotFoundError(Exception):
        """Fallback error if geoip2 is unavailable."""

        pass

logger = get_logger(__name__)


class Enricher:
    """Enrich IP addresses using optional external resources."""

    def __init__(
        self,
        geoip_city_db_path: Optional[str] = settings.geoip_city_db_path,
        geoip_asn_db_path: Optional[str] = settings.geoip_asn_db_path,
        geoip_country_db_path: Optional[str] = settings.geoip_country_db_path,
    ) -> None:
        """Initialize the Enricher.

        Parameters
        ----------
        geoip_city_db_path:
            Optional path to a GeoIP City database.
        geoip_asn_db_path:
            Optional path to a GeoIP ASN database.
        """

        self.geoip_city_db_path = geoip_city_db_path
        self.geoip_asn_db_path = geoip_asn_db_path
        self.geoip_country_db_path = geoip_country_db_path
        self.geoip_city_reader: Reader | None = None
        self.geoip_asn_reader: Reader | None = None
        self.geoip_country_reader: Reader | None = None
        self._rdns_lookup_cached: Callable[[str], Optional[str]] | None = None
        self._country_lookup_cached: Callable[[str], str | None] | None = None
        self._geoip_lookup_cached: Callable[[str], Optional[dict]] | None = None
        self._asn_lookup_cached: Callable[[str], Optional[dict]] | None = None
        self.packet_cache = PacketCache(settings.packet_cache_size, settings.cache_enabled)
        
        if geoip_city_db_path and geoip2 is not None:
            logger.debug("GeoIP City database path provided: %s", geoip_city_db_path)
            try:
                self.geoip_city_reader = geoip2.database.Reader(geoip_city_db_path)
                self._geoip_lookup_cached = self.packet_cache.memoize(self._geoip_lookup)
            except Exception:
                logger.exception("Failed to open GeoIP City database at %s", geoip_city_db_path)

        if geoip_asn_db_path and geoip2 is not None:
            logger.debug("GeoIP ASN database path provided: %s", geoip_asn_db_path)
            try:
                self.geoip_asn_reader = geoip2.database.Reader(geoip_asn_db_path)
                self._asn_lookup_cached = self.packet_cache.memoize(self._asn_lookup)
            except Exception:
                logger.exception("Failed to open GeoIP ASN database at %s", geoip_asn_db_path)

        if geoip_country_db_path and geoip2 is not None:
            logger.debug("GeoIP Country database path provided: %s", geoip_country_db_path)
            try:
                self.geoip_country_reader = geoip2.database.Reader(geoip_country_db_path)
                self._country_lookup_cached = self.packet_cache.memoize(self._lookup_country)
            except Exception:
                logger.exception("Failed to open GeoIP Country database at %s", geoip_country_db_path)

        self._rdns_lookup_cached = self.packet_cache.memoize(self._lookup_rdns)

    def enrich_ips(self, ips: list[str]) -> dict[str, dict[str, Any]]:
        """Return enrichment information for a list of IP addresses."""
        results: dict[str, dict[str, Any]] = {}
        for ip in ips:
            logger.debug("Enriching IP: %s", ip)
            results[ip] = {
                "geo": self.get_geoip(ip),
                "asn": self.get_asn(ip),
                "rdns": self.get_rdns(ip),
            }
        return results

    def get_geoip(self, ip: str) -> Optional[dict]:
        """Lookup GeoIP information for an IP address."""
        logger.debug("GeoIP lookup for: %s", ip)
        if self._geoip_lookup_cached is None:
            return None
        return self._geoip_lookup_cached(ip)

    def get_asn(self, ip: str) -> Optional[dict]:
        """Lookup ASN information for an IP address."""
        logger.debug("ASN lookup for: %s", ip)
        if self._asn_lookup_cached is None:
            return None
        return self._asn_lookup_cached(ip)

    def get_rdns(self, ip: str, timeout: float | None = 2.0) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address."""
        logger.debug("rDNS lookup for: %s", ip)

        if timeout == 2.0 and self._rdns_lookup_cached is not None:
            return self._rdns_lookup_cached(ip)

        return self._lookup_rdns(ip, timeout)

    def _lookup_rdns(self, ip: str, timeout: float | None = 2.0) -> Optional[str]:
        old_timeout: float | None = None
        try:
            if timeout is not None:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(timeout)
            host, *_ = socket.gethostbyaddr(ip)
            return host
        except (socket.herror, socket.gaierror, TimeoutError):
            logger.info("rDNS lookup failed for %s", ip)
            return None
        finally:
            if timeout is not None:
                socket.setdefaulttimeout(old_timeout)

    def _geoip_lookup(self, ip: str) -> Optional[dict]:
        if not self.geoip_city_reader or geoip2 is None:
            return None
        try:
            resp = self.geoip_city_reader.city(ip)
        except AddressNotFoundError:
            logger.info("GeoIP address not found: %s", ip)
            return None
        except Exception:
            logger.exception("GeoIP lookup failed for %s", ip)
            return None
        return {
            "country": getattr(resp.country, "name", None),
            "city": getattr(resp.city, "name", None),
            "latitude": getattr(resp.location, "latitude", None),
            "longitude": getattr(resp.location, "longitude", None),
        }

    def _asn_lookup(self, ip: str) -> Optional[dict]:
        if not self.geoip_asn_reader or geoip2 is None:
            return None
        try:
            resp = self.geoip_asn_reader.asn(ip)
        except AddressNotFoundError:
            logger.info("ASN address not found: %s", ip)
            return None
        except Exception:
            logger.exception("ASN lookup failed for %s", ip)
            return None
        return {
            "number": getattr(resp, "autonomous_system_number", None),
            "organization": getattr(resp, "autonomous_system_organization", None),
        }

    def _lookup_country(self, ip: str) -> Optional[str]:
        if not self.geoip_country_reader or geoip2 is None:
            return None
        try:
            resp = self.geoip_country_reader.country(ip)
        except AddressNotFoundError:
            logger.info("GeoIP country not found: %s", ip)
            return None
        except Exception:
            logger.exception("GeoIP country lookup failed for %s", ip)
            return None
        return getattr(resp.country, "iso_code", None)

    def get_country(self, ip: str) -> Optional[str]:
        """Return the ISO country code for ``ip`` if available."""
        if self._country_lookup_cached is None:
            return None
        return self._country_lookup_cached(ip)

    # --- cache utilities -------------------------------------------------

    def cache_info(self) -> dict[str, Any]:
        info: dict[str, Any] = {}
        for name, func in {
            "country": self._country_lookup_cached,
            "geoip": self._geoip_lookup_cached,
            "asn": self._asn_lookup_cached,
            "rdns": self._rdns_lookup_cached,
        }.items():
            if func is not None and hasattr(func, "cache_info"):
                info[name] = func.cache_info()
        return info

    def clear_cache(self) -> None:
        for func in [
            self._country_lookup_cached,
            self._geoip_lookup_cached,
            self._asn_lookup_cached,
            self._rdns_lookup_cached,
        ]:
            if func is not None and hasattr(func, "cache_clear"):
                func.cache_clear()

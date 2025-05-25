"""IP enrichment utilities."""

from __future__ import annotations

from pcap_tool.logging import get_logger
from ..core.config import settings
from ..core.dependencies import container
import socket
from functools import lru_cache
from typing import Any, Callable, Optional

geoip2 = None
Reader = None  # type: ignore

if container.is_available("geoip2"):
    geoip2 = container.get("geoip2")  # type: ignore
    import importlib
    database_mod = importlib.import_module("geoip2.database")
    errors_mod = importlib.import_module("geoip2.errors")
    Reader = database_mod.Reader  # type: ignore
    AddressNotFoundError = errors_mod.AddressNotFoundError  # type: ignore
else:
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
        self._rdns_cache: dict[str, str | None] = {}
        self._country_lookup_cached: Callable[[str], str | None] | None = None

        if geoip_city_db_path and geoip2 is not None:
            logger.debug("GeoIP City database path provided: %s", geoip_city_db_path)
            try:
                self.geoip_city_reader = geoip2.database.Reader(geoip_city_db_path)
            except Exception:
                logger.exception("Failed to open GeoIP City database at %s", geoip_city_db_path)

        if geoip_asn_db_path and geoip2 is not None:
            logger.debug("GeoIP ASN database path provided: %s", geoip_asn_db_path)
            try:
                self.geoip_asn_reader = geoip2.database.Reader(geoip_asn_db_path)
            except Exception:
                logger.exception("Failed to open GeoIP ASN database at %s", geoip_asn_db_path)

        if geoip_country_db_path and geoip2 is not None:
            logger.debug("GeoIP Country database path provided: %s", geoip_country_db_path)
            try:
                self.geoip_country_reader = geoip2.database.Reader(geoip_country_db_path)
                self._country_lookup_cached = lru_cache(maxsize=10000)(self._lookup_country)  # type: ignore[misc]
            except Exception:
                logger.exception("Failed to open GeoIP Country database at %s", geoip_country_db_path)

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

    def get_asn(self, ip: str) -> Optional[dict]:
        """Lookup ASN information for an IP address."""
        logger.debug("ASN lookup for: %s", ip)
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

    def get_rdns(self, ip: str, timeout: float | None = 2.0) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address."""
        logger.debug("rDNS lookup for: %s", ip)

        if ip in self._rdns_cache:
            return self._rdns_cache[ip]

        old_timeout: float | None = None
        try:
            if timeout is not None:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(timeout)
            host, *_ = socket.gethostbyaddr(ip)
            self._rdns_cache[ip] = host
            return host
        except (socket.herror, socket.gaierror, TimeoutError):
            logger.info("rDNS lookup failed for %s", ip)
            self._rdns_cache[ip] = None
            return None
        finally:
            if timeout is not None:
                socket.setdefaulttimeout(old_timeout)

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

"""IP enrichment utilities."""

from __future__ import annotations

import logging
from typing import Any, Optional

try:
    from geoip2.database import Reader
    from geoip2.errors import AddressNotFoundError
except Exception:  # pragma: no cover - library may not be installed
    Reader = None  # type: ignore

    class AddressNotFoundError(Exception):
        """Fallback error if geoip2 is unavailable."""

        pass

logger = logging.getLogger(__name__)


class Enricher:
    """Enrich IP addresses using optional external resources."""

    def __init__(
        self,
        geoip_city_db_path: Optional[str] = None,
        geoip_asn_db_path: Optional[str] = None,
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
        self.geoip_city_reader: Reader | None = None
        self.geoip_asn_reader: Reader | None = None

        if geoip_city_db_path and Reader is not None:
            logger.debug("GeoIP City database path provided: %s", geoip_city_db_path)
            try:
                self.geoip_city_reader = Reader(geoip_city_db_path)
            except Exception:
                logger.exception("Failed to open GeoIP City database at %s", geoip_city_db_path)

        if geoip_asn_db_path and Reader is not None:
            logger.debug("GeoIP ASN database path provided: %s", geoip_asn_db_path)
            try:
                self.geoip_asn_reader = Reader(geoip_asn_db_path)
            except Exception:
                logger.exception("Failed to open GeoIP ASN database at %s", geoip_asn_db_path)

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
        if not self.geoip_city_reader or Reader is None:
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
        if not self.geoip_asn_reader or Reader is None:
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

    def get_rdns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address."""
        logger.debug("rDNS lookup for: %s", ip)
        return None  # Placeholder implementation

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration loaded from environment variables or .env file."""

    # Parser settings
    default_parser: str = Field("pyshark", description="Preferred parser backend")
    chunk_size: int = Field(10_000, description="Rows per DataFrame chunk")
    max_workers: Optional[int] = Field(None, description="Maximum parser workers")

    # Enrichment settings
    geoip_city_db_path: Optional[str] = None
    geoip_asn_db_path: Optional[str] = None
    geoip_country_db_path: Optional[str] = None

    # Analysis settings
    tcp_rtt_timeout: float = Field(3.0, description="TCP handshake RTT timeout")
    retransmission_threshold: float = Field(
        1.0,
        description="Retransmission ratio percentage considered degraded",
    )

    # Caching settings
    cache_enabled: bool = Field(True, description="Enable caching of common lookups")
    flow_cache_size: int = Field(10000, description="Maximum entries in flow cache")
    packet_cache_size: int = Field(10000, description="Maximum entries in packet cache")

    # Reporting settings
    pdf_report_max_flows: int = Field(20, description="Top flows to include in PDF")

    class Config:
        env_prefix = "PCAP_TOOL_"
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    """Return a singleton settings instance."""
    return Settings()


settings = get_settings()

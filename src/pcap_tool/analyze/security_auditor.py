"""Security auditing utilities for tagged flow data."""

from __future__ import annotations

from typing import Dict, List
import pandas as pd

from ..enrichment import Enricher


class SecurityAuditor:
    """Summarize security related findings from flows."""

    UNUSUAL_COUNTRIES = {"North Korea", "Iran", "Syria", "Sudan"}

    def __init__(self, enricher: Enricher) -> None:
        self.enricher = enricher

    def audit_flows(
        self, tagged_flow_df: pd.DataFrame, unique_external_ips: List[str]
    ) -> Dict[str, object]:
        """Return aggregated security findings for the provided flows."""
        result: Dict[str, object] = {
            "plaintext_http_flows": 0,
            "outdated_tls_version_counts": {},
            "self_signed_certificate_flows": 0,
            "connections_to_unusual_countries": {},
        }

        if not tagged_flow_df.empty:
            plaintext_series = tagged_flow_df.get(
                "security_flag_plaintext_http", pd.Series(dtype=bool)
            )
            result["plaintext_http_flows"] = int(
                plaintext_series.fillna(False).astype(bool).sum()
            )

            if "security_flag_outdated_tls_version" in tagged_flow_df.columns:
                counts = (
                    tagged_flow_df["security_flag_outdated_tls_version"]
                    .dropna()
                    .astype(str)
                    .value_counts()
                    .to_dict()
                )
                result["outdated_tls_version_counts"] = counts

            self_signed_series = tagged_flow_df.get(
                "security_flag_self_signed_cert", pd.Series(dtype=bool)
            )
            result["self_signed_certificate_flows"] = int(
                self_signed_series.fillna(False).astype(bool).sum()
            )

        enriched_ips = self.enricher.enrich_ips(unique_external_ips)
        unusual_connections: Dict[str, str] = {}

        for idx, row in tagged_flow_df.iterrows():
            dest_ip = row.get("destination_ip")
            if pd.isna(dest_ip):
                continue
            info = enriched_ips.get(str(dest_ip))
            if not info:
                continue
            country = (info.get("geo") or {}).get("country")
            if country in self.UNUSUAL_COUNTRIES:
                flow_id = row.get("flow_id")
                flow_key = str(flow_id) if pd.notna(flow_id) else str(idx)
                unusual_connections[flow_key] = country

        result["connections_to_unusual_countries"] = unusual_connections
        return result

"""Security auditing utilities for tagged flow data."""

from __future__ import annotations

from typing import Dict, List, TYPE_CHECKING
import pandas as pd
from ...utils import coalesce
from ...core.decorators import handle_analysis_errors, log_performance

if TYPE_CHECKING:  # pragma: no cover - for type hints only
    from ...enrichment import Enricher


class SecurityAuditor:
    """Summarize security related findings from flows."""

    DEFAULT_COMMON_COUNTRIES = {"US", "CA", "GB", "DE", "FR", "NL", "JP", "AU"}

    def __init__(self, enricher: Enricher) -> None:
        self.enricher = enricher

    @handle_analysis_errors
    @log_performance
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
                coalesce(plaintext_series, False).astype(bool).sum()
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
                coalesce(self_signed_series, False).astype(bool).sum()
            )

        unusual_connections: Dict[str, str] = {}

        if "dest_country" in tagged_flow_df.columns:
            is_unusual = tagged_flow_df.get("is_unusual_country")
            if is_unusual is None:
                is_unusual = tagged_flow_df["dest_country"].apply(
                    lambda c: False if pd.isna(c) or c in self.DEFAULT_COMMON_COUNTRIES else True
                )
            for idx, row in tagged_flow_df.iterrows():
                if not is_unusual.iloc[idx]:
                    continue
                country = row.get("dest_country")
                flow_id = row.get("flow_id")
                flow_key = str(flow_id) if pd.notna(flow_id) else str(idx)
                if pd.notna(country):
                    unusual_connections[flow_key] = str(country)
        else:
            enriched_ips = self.enricher.enrich_ips(unique_external_ips)
            for idx, row in tagged_flow_df.iterrows():
                dest_ip = row.get("destination_ip", row.get("dest_ip"))
                if pd.isna(dest_ip):
                    continue
                country = self.enricher.get_country(str(dest_ip))
                if not country:
                    info = enriched_ips.get(str(dest_ip))
                    country = (info.get("geo") or {}).get("country") if info else None
                if country and country not in self.DEFAULT_COMMON_COUNTRIES:
                    flow_id = row.get("flow_id")
                    flow_key = str(flow_id) if pd.notna(flow_id) else str(idx)
                    unusual_connections[flow_key] = country

        result["connections_to_unusual_countries"] = unusual_connections
        return result

    @handle_analysis_errors
    @log_performance
    def get_total_security_issue_count(self, security_findings: Dict[str, object]) -> int:
        """Return the total number of security issues in ``security_findings``."""
        count = 0
        count += int(security_findings.get("plaintext_http_flows") or 0)
        count += int(security_findings.get("self_signed_certificate_flows") or 0)
        outdated = security_findings.get("outdated_tls_version_counts") or {}
        if isinstance(outdated, dict):
            count += sum(int(v) for v in outdated.values())
        unusual = security_findings.get("connections_to_unusual_countries") or {}
        if isinstance(unusual, dict):
            count += len(unusual)
        return count

"""Utilities to build a consolidated metrics dictionary."""

from __future__ import annotations

from pcap_tool.logging import get_logger
from typing import Any, Dict, List

import re

import pandas as pd

from .metrics.flow_table import FlowTable
from .metrics.stats_collector import StatsCollector
from .metrics.timeline_builder import TimelineBuilder
from .enrichment import Enricher
from .enrich.service_guesser import guess_service
from .analyze import PerformanceAnalyzer, ErrorSummarizer, SecurityAuditor
from heuristics.engine import HeuristicEngine

logger = get_logger(__name__)

# Country codes considered "common" in most enterprise traffic. Connections to
# destinations outside this set are flagged as unusual.
DEFAULT_COMMON_COUNTRIES = {"US", "CA", "GB", "DE", "FR", "NL", "JP", "AU"}

# Scoring constants used in select_top_flows
SCORE_BLOCKED_DISPOSITION = 1000
SCORE_DEGRADED_DISPOSITION = 500
SECURITY_OBS_MULTIPLIER = 200
SECURITY_OBS_FALLBACK = 200
BYTES_TOTAL_DIVISOR = 1_000_000


def select_top_flows(flows_df: pd.DataFrame, count: int = 20) -> pd.DataFrame:
    """Return flows ordered by diagnostic relevance."""

    if flows_df is None or flows_df.empty:
        return flows_df

    def _score(row: pd.Series) -> float:
        score = 0.0

        disposition = str(row.get("flow_disposition", ""))
        if disposition.startswith("Blocked"):
            score += SCORE_BLOCKED_DISPOSITION
        elif "Degraded" in disposition:
            score += SCORE_DEGRADED_DISPOSITION

        obs = row.get("security_observations")
        if obs is None:
            obs = row.get("security_observation")

        # ``obs`` may be None, an empty string, the literal string "None",
        # or a sequence of observations. Only non-empty values contribute to the score.
        if isinstance(obs, str):
            cleaned = obs.strip()
            if cleaned and cleaned.lower() != "none":
                tokens = [o for o in re.split(r"[;,]+", cleaned) if o.strip()]
                score += SECURITY_OBS_MULTIPLIER * len(tokens)
        elif obs not in (None, ""):
            try:
                score += SECURITY_OBS_MULTIPLIER * len(obs)
            except TypeError:
                logger.warning(
                    "Could not determine length of security observations: %r, type: %s",
                    obs,
                    type(obs),
                )
                score += SECURITY_OBS_FALLBACK
            except Exception as exc:
                logger.error(
                    "Unexpected error processing security observations: %s",
                    exc,
                )
                score += SECURITY_OBS_FALLBACK

        bytes_total = row.get("bytes_total")
        try:
            score += float(bytes_total) / BYTES_TOTAL_DIVISOR
        except (ValueError, TypeError):
            logger.warning(
                'Could not convert bytes_total "%s" to float. Skipping its contribution to score.',
                bytes_total,
            )
        except Exception as exc:
            logger.error(
                'Unexpected error processing bytes_total "%s": %s. Skipping its contribution to score.',
                bytes_total,
                exc,
            )

        return score

    df = flows_df.copy()
    df["__score"] = df.apply(_score, axis=1)
    df = df.sort_values("__score", ascending=False).drop(columns=["__score"])
    return df.head(count)


class MetricsBuilder:
    """Aggregate metrics from various processors."""

    #: Blueprint of the final metrics JSON structure.
    TARGET_SCHEMA = {
        "capture_info": {},
        "protocols": {},
        "top_ports": {},
        "quic_vs_tls_packets": {},
        "top_talkers_by_bytes": [],
        "top_talkers_by_packets": [],
        "service_overview": {},
        "error_summary": {},
        "performance_metrics": {},
        "security_findings": {},
        "timeline_data": [],
    }

    def __init__(
        self,
        stats_collector: StatsCollector,
        flow_table: FlowTable,
        enricher: Enricher,
        service_guesser: Any,
        performance_analyzer: PerformanceAnalyzer,
        timeline_builder: TimelineBuilder,
        error_summarizer: ErrorSummarizer,
        security_auditor: SecurityAuditor,
        heuristic_engine: HeuristicEngine,
    ) -> None:
        self.stats_collector = stats_collector
        self.flow_table = flow_table
        self.enricher = enricher
        self.service_guesser = service_guesser
        self.performance_analyzer = performance_analyzer
        self.timeline_builder = timeline_builder
        self.error_summarizer = error_summarizer
        self.security_auditor = security_auditor
        self.heuristic_engine = heuristic_engine

    def build_metrics(
        self,
        packet_df_for_enrich_detail: pd.DataFrame,
        tagged_flow_df: pd.DataFrame,
    ) -> Dict[str, Any]:
        """Return aggregated metrics in the TARGET_SCHEMA format.

        Many columns in ``tagged_flow_df`` are created from pandas
        aggregations and may have ``NaN`` when no data is present. Before
        converting those values to ``int`` for the metrics JSON, verify them
        with ``pd.notna`` and supply a default such as ``0`` when missing.
        """

        logger.debug("Building metrics dictionary")
        metrics: Dict[str, Any] = {
            "capture_info": {},
            "protocols": {},
            "top_ports": {},
            "quic_vs_tls_packets": {},
            "top_talkers_by_bytes": [],
            "top_talkers_by_packets": [],
            "service_overview": {},
            "error_summary": {},
            "performance_metrics": {},
            "security_findings": {},
            "timeline_data": [],
        }

        # Stats summary
        sc_summary = self.stats_collector.summary()
        metrics["capture_info"] = sc_summary.get("capture_info", {})
        metrics["protocols"] = sc_summary.get("protocols", {})
        metrics["top_ports"] = sc_summary.get("top_ports", {})
        metrics["quic_vs_tls_packets"] = sc_summary.get("quic_vs_tls_packets", {})

        # Flow table summaries
        df_bytes, df_pkts = self.flow_table.get_summary_df()
        metrics["top_talkers_by_bytes"] = df_bytes.to_dict(orient="records")
        metrics["top_talkers_by_packets"] = df_pkts.to_dict(orient="records")

        # Service overview
        service_overview: Dict[str, Dict[str, int]] = {}
        if not tagged_flow_df.empty:
            ip_series = tagged_flow_df.get("destination_ip")
            if ip_series is None:
                ip_series = tagged_flow_df.get("dest_ip", pd.Series(dtype=object))
            unique_external_ips = (
                ip_series.dropna()
                .astype(str)
                .unique()
                .tolist()
            )
            country_map = {ip: self.enricher.get_country(ip) for ip in unique_external_ips}
            dest_country_series = ip_series.astype(str).map(country_map)
            tagged_flow_df["dest_country"] = dest_country_series
            tagged_flow_df["is_unusual_country"] = dest_country_series.apply(
                lambda c: False if pd.isna(c) or c in DEFAULT_COMMON_COUNTRIES else True
            )
        else:
            unique_external_ips = []

        enriched_ips_data = self.enricher.enrich_ips(unique_external_ips)

        for _, row in tagged_flow_df.iterrows():
            dest_ip = row.get("destination_ip", row.get("dest_ip"))
            protocol = row.get("protocol")
            port = row.get("destination_port", row.get("dest_port"))
            sni = row.get("sni") or row.get("server_name_indication")
            http_host = row.get("http_request_host_header")
            ip_info = enriched_ips_data.get(str(dest_ip), {})
            rdns = (ip_info or {}).get("rdns")
            is_quic = bool(row.get("is_quic")) if "is_quic" in row else False
            service = None
            if hasattr(self.service_guesser, "guess_service"):
                service = self.service_guesser.guess_service(
                    protocol,
                    int(port) if pd.notna(port) else None,
                    sni=sni if pd.notna(sni) else None,
                    http_host=http_host if pd.notna(http_host) else None,
                    rdns=rdns,
                    is_quic=is_quic,
                )
            else:
                service = guess_service(
                    protocol,
                    int(port) if pd.notna(port) else None,
                    sni=sni if pd.notna(sni) else None,
                    http_host=http_host if pd.notna(http_host) else None,
                    rdns=rdns,
                    is_quic=is_quic,
                )
            entry = service_overview.setdefault(service, {"flow_count": 0, "bytes": 0})
            entry["flow_count"] += 1
            bytes_val = row.get("bytes_total")
            entry["bytes"] += int(bytes_val) if pd.notna(bytes_val) else 0
        metrics["service_overview"] = service_overview

        # Top flows based on diagnostic relevance
        metrics["top_flows"] = (
            select_top_flows(tagged_flow_df).to_dict(orient="records")
            if not tagged_flow_df.empty
            else []
        )

        # Error summary
        metrics["error_summary"] = self.error_summarizer.summarize_errors(tagged_flow_df)

        # Performance metrics
        metrics["performance_metrics"] = self.performance_analyzer.get_summary()

        # Security findings
        metrics["security_findings"] = self.security_auditor.audit_flows(
            tagged_flow_df, unique_external_ips
        )

        # Timeline
        sorted_bins, bytes_list, packets_list = self.timeline_builder.get_timeline_data()
        spike_indices = self.timeline_builder.find_spikes(bytes_list)
        for idx, ts in enumerate(sorted_bins):
            entry: Dict[str, Any] = {
                "timestamp": ts,
                "bytes": bytes_list[idx],
                "packets": packets_list[idx],
                "spike": idx in spike_indices,
                "top_flows": [],
            }
            if entry["spike"] and not tagged_flow_df.empty:
                if {
                    "start_time",
                    "end_time",
                    "bytes_total",
                    "flow_id",
                }.issubset(tagged_flow_df.columns):
                    ts_dt = pd.to_datetime(ts, unit="s")
                    active = tagged_flow_df[
                        (tagged_flow_df["start_time"] <= ts_dt)
                        & (tagged_flow_df["end_time"] >= ts_dt)
                    ]
                    flow_series = active.sort_values("bytes_total", ascending=False).head(5).get(
                        "flow_id",
                        pd.Series(dtype=object),
                    )
                    top_flows = (
                        flow_series.dropna()
                        .astype(str)
                        .tolist()
                    )
                    entry["top_flows"] = top_flows
            metrics["timeline_data"].append(entry)

        return metrics

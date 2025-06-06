"""Utilities to build a consolidated metrics dictionary."""

from __future__ import annotations

from pcap_tool.logging import get_logger
from typing import Any, Dict, List, TYPE_CHECKING
from collections.abc import Iterable

import re

import pandas as pd

from .metrics.flow_table import FlowTable
from .metrics.stats_collector import StatsCollector
from .metrics.timeline_builder import TimelineBuilder
from .enrich.service_guesser import guess_service
from .analyze import PerformanceAnalyzer, ErrorSummarizer, SecurityAuditor
from pcap_tool.heuristics.engine import HeuristicEngine
from pcap_tool.heuristics.metrics import count_tls_versions
from .core.config import settings
from .core.decorators import handle_analysis_errors, log_performance

if TYPE_CHECKING:  # pragma: no cover - imported for type hints only
    from .enrichment import Enricher

logger = get_logger(__name__)

# Country codes considered "common" in most enterprise traffic. Connections to
# destinations outside this set are flagged as unusual.
DEFAULT_COMMON_COUNTRIES = {"US", "CA", "GB", "DE", "FR", "NL", "JP", "AU"}

# Scoring constants used by ``select_top_flows``
SCORE_BLOCKED = 1000
SCORE_DEGRADED = 500
SCORE_PER_SECURITY_OBSERVATION = 200
BYTES_SCORE_DIVISOR = 1_000_000


def select_top_flows(flows_df: pd.DataFrame, count: int = 20) -> pd.DataFrame:
    """Return flows ordered by diagnostic relevance."""

    if flows_df is None or flows_df.empty:
        return flows_df

    def _score(row: pd.Series) -> float:
        score = 0.0
        disposition = str(row.get("flow_disposition", ""))
        if disposition.startswith("Blocked"):
            score += SCORE_BLOCKED
        elif "Degraded" in disposition:
            score += SCORE_DEGRADED

        obs = row.get("security_observations", row.get("security_observation"))
        if isinstance(obs, str):
            cleaned = obs.strip()
            # Check for formally defined 'none' string representing no observation
            if cleaned and cleaned.lower() != "none":
                score += SCORE_PER_SECURITY_OBSERVATION * len(
                    [o for o in re.split(r"[;,]+", cleaned) if o.strip()]
                )
        else:
            if (
                isinstance(obs, Iterable)
                and not isinstance(obs, (str, bytes))
                and hasattr(obs, "__len__")
            ):
                try:
                    obs_len = len(obs)
                except TypeError as exc:
                    # Guard against custom iterables with faulty ``__len__``
                    logger.warning(
                        "TypeError scoring security observations: %s", exc
                    )
                except Exception as exc:  # pragma: no cover - unexpected error
                    logger.error(
                        "Unexpected error scoring security observations: %s", exc
                    )
                else:
                    if obs_len:
                        score += SCORE_PER_SECURITY_OBSERVATION * obs_len

        bytes_total = row.get("bytes_total")
        try:
            score += float(bytes_total) / BYTES_SCORE_DIVISOR
        except Exception as e:
            logger.warning(
                f"Could not process bytes_total '{bytes_total}' for scoring: {e}"
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
        "tls_version_counts": {},
        "top_talkers_by_bytes": [],
        "top_talkers_by_packets": [],
        "service_overview": {},
        "error_summary": {},
        "performance_metrics": {
            "tcp_rtt_ms": {},
            "tcp_syn_rtt_ms": None,
            "tls_time_to_alert_ms": None,
            "tcp_retransmission_ratio_percent": 0.0,
            "rtt_limited_data": False,
        },
        "security_findings": {},
        "timeline_data": [],
    }

    def __init__(
        self,
        stats_collector: StatsCollector,
        flow_table: FlowTable,
        enricher: "Enricher",
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

    @handle_analysis_errors
    @log_performance
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
            "tls_version_counts": {},
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
        if (
            not packet_df_for_enrich_detail.empty
            and "tls_effective_version" in packet_df_for_enrich_detail.columns
        ):
            # Extract only the column required for TLS version counting to avoid
            # allocating full row dictionaries when the DataFrame has many
            # columns. The generator yields minimal mappings accepted by
            # ``count_tls_versions``.
            column_values = packet_df_for_enrich_detail[
                "tls_effective_version"
            ].dropna()
            records_for_count = (
                {"tls_effective_version": val} for val in column_values
            )
            metrics["tls_version_counts"] = count_tls_versions(records_for_count)
        else:
            metrics["tls_version_counts"] = {}

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
            select_top_flows(tagged_flow_df, settings.pdf_report_max_flows).to_dict(orient="records")
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

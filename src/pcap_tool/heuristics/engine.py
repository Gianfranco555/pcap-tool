from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Optional

from pcap_tool.logging import get_logger
from .dns_tls_mismatch import detect_dns_sni_mismatch
from pcap_tool.parsers.tls import get_tls_handshake_outcome
from pcap_tool.enrichment.icmp_correlator import correlate_icmp_errors

_LegacyHeuristicEngine = None
_legacy_heuristic_engine_import_error: Optional[Exception] = None

try:  # pragma: no cover - optional dependency
    from heuristics.engine import HeuristicEngine as _ImportedLegacyHeuristicEngine  # type: ignore
    # use the legacy engine when available
    _LegacyHeuristicEngine = _ImportedLegacyHeuristicEngine
except (ImportError, ModuleNotFoundError) as e:  # pragma: no cover - fallback if not available
    _legacy_heuristic_engine_import_error = e


logger = get_logger(__name__)

import pandas as pd
import yaml


def _is_http_407(df: pd.DataFrame) -> pd.Series:
    """Return True for HTTP flows with status 407."""
    proto = df.get("proto") if "proto" in df.columns else df.get("protocol")
    status = (
        df.get("http_status")
        if "http_status" in df.columns
        else df.get("http_response_code")
    )
    return (proto == "HTTP") & (status == 407)


class VectorisedHeuristicEngine:
    """Simple flow heuristic engine based on vectorised pandas operations."""

    def __init__(self, rules_path: Optional[str] = None) -> None:
        if rules_path is None:
            rules_path = Path(__file__).with_name("rules.yaml")
        with open(rules_path, "r") as fh:
            cfg = yaml.safe_load(fh) or {}
        self.rules = cfg.get("rules", [])
        self._predicate_map: Dict[str, Callable[[pd.DataFrame], pd.Series]] = {
            "allowed": lambda df: df.get("handshake_complete", False)
            & df.get("data_both", False),
            "blocked_rst": lambda df: df.get("rst_after_syn", False),
            "icmp_degraded": lambda df: df.get("icmp_error", False),
            "any": lambda df: pd.Series([True] * len(df), index=df.index),
        }
        self._predicate_map["http_407"] = _is_http_407

        proxy_rule = {
            "name": "proxy_auth_failure",
            "predicate": "http_407",
            "flow_disposition": "Blocked",
            "flow_cause": "Proxy Authentication Failed",
        }
        try:
            idx = next(i for i, r in enumerate(self.rules) if r.get("name") == "Unknown")
            self.rules.insert(idx, proxy_rule)
        except StopIteration:
            self.rules.append(proxy_rule)

    def _aggregate_flows(self, packets: pd.DataFrame) -> pd.DataFrame:
        cols = [
            "client_ip",
            "server_ip",
            "client_port",
            "server_port",
            "protocol",
        ]
        df = packets.copy()
        orient_col = None
        if "is_source_client" in df.columns:
            orient_col = "is_source_client"
        elif "is_src_client" in df.columns:
            orient_col = "is_src_client"
        if orient_col is None:
            raise ValueError("is_source_client column required for heuristics")

        df["client_ip"] = df.apply(
            lambda r: r["source_ip"] if r[orient_col] else r["destination_ip"],
            axis=1,
        )
        df["server_ip"] = df.apply(
            lambda r: r["destination_ip"] if r[orient_col] else r["source_ip"],
            axis=1,
        )
        df["client_port"] = df.apply(
            lambda r: r["source_port"] if r[orient_col] else r["destination_port"],
            axis=1,
        )
        df["server_port"] = df.apply(
            lambda r: r["destination_port"] if r[orient_col] else r["source_port"],
            axis=1,
        )

        for flag in ["tcp_flags_syn", "tcp_flags_ack", "tcp_flags_psh", "tcp_flags_rst"]:
            if flag in df.columns:
                df[flag] = df[flag].fillna(False)
            else:
                df[flag] = False
        if "icmp_type" not in df.columns:
            df["icmp_type"] = pd.NA
        if "timestamp" not in df.columns:
            df["timestamp"] = pd.NA

        groups = df.groupby(cols)
        index = groups.size().index

        client_mask = df[orient_col] == True
        server_mask = df[orient_col] == False

        first_syn = (
            df[client_mask & df.tcp_flags_syn & ~df.tcp_flags_ack]
            .groupby(cols)["timestamp"]
            .min()
        )
        synack_seen = (
            df[server_mask & df.tcp_flags_syn & df.tcp_flags_ack]
            .groupby(cols)
            .size()
            .gt(0)
        )
        ack_seen = (
            df[client_mask & df.tcp_flags_ack & ~df.tcp_flags_syn]
            .groupby(cols)
            .size()
            .gt(0)
        )

        handshake_complete = (
            first_syn.notna()
            & synack_seen.reindex(first_syn.index, fill_value=False)
            & ack_seen.reindex(first_syn.index, fill_value=False)
        )
        handshake_complete_full = pd.Series(False, index=index)
        handshake_complete_full.loc[handshake_complete.index] = handshake_complete

        data_client = (
            df[client_mask & df.tcp_flags_psh]
            .groupby(cols)
            .size()
            .gt(0)
        )
        data_server = (
            df[server_mask & df.tcp_flags_psh]
            .groupby(cols)
            .size()
            .gt(0)
        )
        data_both = (data_client & data_server).reindex(index, fill_value=False)

        rst_time = (
            df[server_mask & df.tcp_flags_rst]
            .groupby(cols)["timestamp"]
            .min()
        )
        first_syn_full = first_syn.reindex(index)
        rst_time_full = rst_time.reindex(index)
        rst_after_syn = (
            (rst_time_full - first_syn_full <= 2)
            & rst_time_full.notna()
            & first_syn_full.notna()
        ).fillna(False)

        icmp_error = (
            df[
                df["protocol"].str.upper().isin(["ICMP", "ICMPV6"])
                & df["icmp_type"].isin([3, 11])
            ]
            .groupby(cols)
            .size()
            .gt(0)
            .reindex(index, fill_value=False)
        )

        flow_df = pd.DataFrame(list(index), columns=cols)
        flow_df = flow_df.reset_index(drop=True)
        flow_df["flow_id"] = flow_df.index
        flow_df["handshake_complete"] = handshake_complete_full.values
        flow_df["data_both"] = data_both.values
        flow_df["rst_after_syn"] = rst_after_syn.values
        flow_df["icmp_error"] = icmp_error.values
        flow_df["icmp_error_count"] = 0
        flow_df["first_syn_time"] = first_syn_full.values
        flow_df["first_rst_time"] = rst_time_full.values
        return flow_df

    def _apply_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df["flow_disposition"] = ""
        df["flow_cause"] = ""

        # ensure predicate registered each call
        self._predicate_map.setdefault("http_407", _is_http_407)

        remaining = pd.Series(True, index=df.index)
        for rule in self.rules:
            pred_key = rule.get("predicate")
            disposition = rule.get("flow_disposition", "")
            cause = rule.get("flow_cause", "")
            pred = self._predicate_map.get(pred_key)
            if pred is None:
                continue
            mask = pred(df) & remaining
            df.loc[mask, "flow_disposition"] = disposition
            df.loc[mask, "flow_cause"] = cause
            remaining &= ~mask
        return df

    def tag_flows(self, packets_df: pd.DataFrame) -> pd.DataFrame:
        flows = self._aggregate_flows(packets_df)

        # correlate downstream ICMP errors with the originating flows
        flows = correlate_icmp_errors(packets_df, flows)

        tls_outcome = get_tls_handshake_outcome(packets_df)
        if tls_outcome.empty:
            flows["tls_handshake_ok"] = pd.NA
            flows["first_alert_time"] = pd.NA
            flows["time_to_alert"] = pd.NA
        else:
            flows = flows.merge(tls_outcome, on="flow_id", how="left")

        tagged = self._apply_rules(flows)

        mismatch = detect_dns_sni_mismatch(tagged)
        if not mismatch.empty:
            tagged = tagged.merge(
                mismatch,
                on="flow_id",
                how="left",
                suffixes=("", "_dns"),
            )
            update_mask = (
                tagged["flow_disposition"].isin(["", "Unknown"])
                & tagged["flow_disposition_dns"].notna()
            )
            tagged.loc[update_mask, "flow_disposition"] = tagged.loc[
                update_mask, "flow_disposition_dns"
            ]
            tagged.loc[update_mask, "flow_cause"] = tagged.loc[
                update_mask, "flow_cause_dns"
            ]
            tagged = tagged.drop(columns=["flow_disposition_dns", "flow_cause_dns"])

        # apply TLS handshake outcome override
        mask_fail = tagged["tls_handshake_ok"] == False
        tagged.loc[mask_fail, "flow_disposition"] = "Blocked"
        tagged.loc[mask_fail, "flow_cause"] = "TLS Handshake Failure"

        # heuristic: degraded flows indicated only by downstream ICMP errors
        icmp_mask = (
            tagged.get("icmp_error_count", 0) > 0
        ) & (tagged["flow_disposition"].isin(["", "Unknown"]))
        tagged.loc[icmp_mask, "flow_disposition"] = "Degraded"
        tagged.loc[icmp_mask, "flow_cause"] = "Downstream ICMP errors"

        return tagged[
            [
                "flow_id",
                "client_ip",
                "server_ip",
                "client_port",
                "server_port",
                "protocol",
                "flow_disposition",
                "flow_cause",
                "icmp_error_count",
                "tls_handshake_ok",
                "first_alert_time",
                "time_to_alert",
            ]
        ]


if _LegacyHeuristicEngine is not None:
    HeuristicEngine = _LegacyHeuristicEngine  # type: ignore
else:  # pragma: no cover - runtime warning
    logger.warning(
        "Legacy heuristics engine could not be imported: %s. Falling back to VectorisedHeuristicEngine.",
        _legacy_heuristic_engine_import_error,
    )
    HeuristicEngine = VectorisedHeuristicEngine

__all__ = ["VectorisedHeuristicEngine", "HeuristicEngine"]

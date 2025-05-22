from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Optional

# Compatibility import: expose the "HeuristicEngine" used by older modules
try:  # pragma: no cover - optional dependency
    from heuristics.engine import HeuristicEngine as HeuristicEngine  # type: ignore
except Exception:  # pragma: no cover - fallback if not available
    HeuristicEngine = None

import pandas as pd
import yaml


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
        flow_df["handshake_complete"] = handshake_complete_full.values
        flow_df["data_both"] = data_both.values
        flow_df["rst_after_syn"] = rst_after_syn.values
        flow_df["icmp_error"] = icmp_error.values
        flow_df["first_syn_time"] = first_syn_full.values
        flow_df["first_rst_time"] = rst_time_full.values
        return flow_df

    def _apply_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df["flow_disposition"] = ""
        df["flow_cause"] = ""
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
        return self._apply_rules(flows)[
            [
                "client_ip",
                "server_ip",
                "client_port",
                "server_port",
                "protocol",
                "flow_disposition",
                "flow_cause",
            ]
        ]


__all__ = ["VectorisedHeuristicEngine"]
if HeuristicEngine is not None:  # pragma: no cover - only if available
    __all__.append("HeuristicEngine")

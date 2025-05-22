"""Utilities to summarize error indicators on flows."""

from __future__ import annotations

from typing import Dict, List
import pandas as pd


class ErrorSummarizer:
    """Aggregate flow error tags from :class:`HeuristicEngine`."""

    def summarize_errors(self, tagged_flow_df: pd.DataFrame) -> Dict[str, Dict]:
        """Return counts and sample flow IDs for each error type."""
        if tagged_flow_df.empty or "flow_error_type" not in tagged_flow_df.columns:
            return {}

        df = tagged_flow_df.dropna(subset=["flow_error_type"]).copy()
        result: Dict[str, Dict] = {}
        for err_type, type_group in df.groupby("flow_error_type"):
            err_type_str = str(err_type)
            if "flow_error_details" in type_group.columns:
                details_dict: Dict[str, Dict[str, object]] = {}
                for detail, detail_group in type_group.groupby("flow_error_details"):
                    detail_key = str(detail) if pd.notna(detail) else "other"
                    flow_series = detail_group.get(
                        "flow_id", pd.Series(dtype=object)
                    )
                    sample_ids: List[str] = (
                        flow_series.dropna()
                        .astype(str)
                        .unique()
                        .tolist()[:3]
                    )
                    details_dict[detail_key] = {
                        "count": int(len(detail_group)),
                        "sample_flow_ids": sample_ids,
                    }
                result[err_type_str] = details_dict
            else:
                flow_series = type_group.get("flow_id", pd.Series(dtype=object))
                sample_ids = (
                    flow_series.dropna()
                    .astype(str)
                    .unique()
                    .tolist()[:3]
                )
                result[err_type_str] = {
                    "count": int(len(type_group)),
                    "sample_flow_ids": sample_ids,
                }
        return result

    def get_total_error_count(self, error_summary: Dict[str, Dict]) -> int:
        """Return the total number of errors from ``error_summary``."""
        total = 0
        for info in error_summary.values():
            if isinstance(info, dict) and "count" in info:
                total += int(info.get("count", 0))
            elif isinstance(info, dict):
                for detail in info.values():
                    if isinstance(detail, dict):
                        total += int(detail.get("count", 0))
        return total

    def get_error_details_for_dataframe(self, error_summary: Dict[str, Dict]) -> List[Dict[str, object]]:
        """Convert ``error_summary`` to a list of dicts for DataFrame display."""
        rows: List[Dict[str, object]] = []
        for err_type, info in error_summary.items():
            if isinstance(info, dict) and "count" in info:
                rows.append({
                    "Type": err_type,
                    "Description": "",
                    "Count": info.get("count", 0),
                })
            elif isinstance(info, dict):
                for detail, d in info.items():
                    if isinstance(d, dict):
                        rows.append({
                            "Type": err_type,
                            "Description": detail,
                            "Count": d.get("count", 0),
                        })
        return rows

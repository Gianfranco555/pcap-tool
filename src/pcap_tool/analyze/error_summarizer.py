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
                    sample_ids: List[str] = (
                        detail_group.get("flow_id")
                        .dropna()
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
                sample_ids = (
                    type_group.get("flow_id")
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()[:3]
                )
                result[err_type_str] = {
                    "count": int(len(type_group)),
                    "sample_flow_ids": sample_ids,
                }
        return result

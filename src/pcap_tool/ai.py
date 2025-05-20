from __future__ import annotations

import pandas as pd


def prepare_ai_data(flows_df: pd.DataFrame, capture_info: dict | None = None) -> dict:
    """Return a simplified structure for AI models.

    Parameters
    ----------
    flows_df:
        DataFrame of flow summaries.
    capture_info:
        Optional capture metadata to include.
    """
    capture = capture_info or {}
    result = {"capture_info": capture, "flows": []}
    if flows_df is not None and not flows_df.empty:
        result["flows"] = flows_df.to_dict(orient="records")
    return result

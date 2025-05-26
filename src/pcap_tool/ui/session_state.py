from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd
import streamlit as st


@dataclass
class AppState:
    metrics_output: dict | None = None
    tagged_flow_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    text_summary: str = ""
    pdf_bytes: bytes = b""
    analysis_ran: bool = False


def get_state() -> AppState:
    if "ui_state" not in st.session_state:
        st.session_state["ui_state"] = AppState()
    return st.session_state["ui_state"]

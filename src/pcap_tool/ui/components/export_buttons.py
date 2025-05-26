from __future__ import annotations

import pandas as pd
import streamlit as st


def export_buttons(tagged_flow_df: pd.DataFrame, pdf_bytes: bytes) -> None:
    csv_data = b""
    pdf_data = b""
    download_disabled = True
    pdf_disabled = True
    if not tagged_flow_df.empty:
        csv_data = tagged_flow_df.to_csv(index=False).encode("utf-8")
        download_disabled = False
    if pdf_bytes:
        pdf_data = pdf_bytes
        pdf_disabled = False
    st.download_button(
        "⬇️  Download Tagged Flows CSV",
        csv_data,
        file_name="tagged_flows.csv",
        mime="text/csv",
        disabled=download_disabled,
    )
    st.download_button(
        "Download PDF Report",
        pdf_data,
        file_name="analysis_report.pdf",
        disabled=pdf_disabled,
    )

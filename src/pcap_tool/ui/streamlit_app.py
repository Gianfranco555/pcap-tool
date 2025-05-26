from __future__ import annotations

from pathlib import Path

import streamlit as st

from pcap_tool.ui.session_state import get_state
from pcap_tool.ui.callbacks import analyze_pcap
from pcap_tool.ui.components.file_uploader import file_uploader
from pcap_tool.ui.components.metrics_display import (
    display_errors,
    display_overview,
    display_timeline,
)
from pcap_tool.ui.components.flow_table import display_flow_table
from pcap_tool.ui.components.export_buttons import export_buttons


st.set_page_config(page_title="PCAP Analysis Tool")
st.title("PCAP Analysis Tool")

THEME_PATH = Path(__file__).resolve().parents[1] / "streamlit_theme.css"
if THEME_PATH.exists():
    st.markdown(f"<style>{THEME_PATH.read_text()}</style>", unsafe_allow_html=True)

state = get_state()

uploaded_file = file_uploader()
output_area = st.empty()

if uploaded_file and st.button("Parse & Analyze"):
    progress = st.progress(0.0, text="Processing PCAP…")

    def update_progress(count: int, total: int | None) -> None:
        value = count / total if total else 0.0
        text = f"Processing PCAP… ({count}/{total})" if total else f"Processing packet {count}"
        progress.progress(min(value, 1.0), text=text)

    rules_path = Path(__file__).resolve().parents[1] / "heuristics" / "rules.yaml"
    try:
        analyze_pcap(uploaded_file, rules_path, state, on_progress=update_progress)
        progress.progress(1.0, text="Analysis complete")
    except Exception as exc:  # pragma: no cover - UI feedback
        progress.empty()
        st.error(f"Error during analysis: {exc}")
    progress.empty()

if state.metrics_output is not None:
    overview_tab, flows_tab, errors_tab, timeline_tab, ai_tab = st.tabs(
        ["Overview", "Flows", "Errors & Security", "Timeline", "AI Summary"]
    )
    with overview_tab:
        display_overview(state.metrics_output)
    with flows_tab:
        display_flow_table(state.tagged_flow_df)
    with errors_tab:
        display_errors(state.metrics_output, state.tagged_flow_df)
    with timeline_tab:
        display_timeline(state.metrics_output)
    with ai_tab:
        st.markdown(state.text_summary)
else:
    if uploaded_file is None:
        output_area.write("Upload a PCAP file to begin analysis.")
    elif not state.analysis_ran:
        output_area.write("Click 'Parse & Analyze' to see results.")
    else:
        output_area.write(
            "No analysis results to display. "
            "Check for errors above or try a different file."
        )

export_buttons(state.tagged_flow_df, state.pdf_bytes)

if __name__ == "__main__":  # pragma: no cover
    print("Run this GUI with:  streamlit run src/pcap_tool/ui/streamlit_app.py")

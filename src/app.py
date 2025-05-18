"""
Phase 6 (Streamlit UI MVP)

Covered user stories US-1 & US-3

Remaining TODOs (hook parser, hook heuristic engine, export logic)
"""

import os
import tempfile
from pathlib import Path

import streamlit as st

from pcap_tool import parse_pcap, generate_pdf_report
from pcap_tool.summary import generate_summary_df
from heuristics.engine import HeuristicEngine

st.set_page_config(page_title="PCAP Analysis Tool")
st.title("PCAP Analysis Tool")

uploaded_file = st.file_uploader(
    "Upload a PCAP or PCAP-ng file (≤ 5 GB)",
    type=["pcap", "pcapng"],
)
if uploaded_file and uploaded_file.size > 5 * 1024 * 1024 * 1024:
    st.error("File exceeds 5 GB limit.")
    uploaded_file = None

output_area = st.empty()
df = None
summary_df = None
analysis_ran = False # From Codex branch

if uploaded_file and st.button("Parse & Analyze"):
    analysis_ran = True
    progress = st.progress(0, text="Parsing PCAP…")
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as tmp:
            tmp.write(uploaded_file.getvalue())
            temp_file_path = tmp.name

        def _on_progress(count: int, total: int | None) -> None:
            percent = count / total if total else 0.0
            progress.progress(min(percent, 1.0), text=f"Parsing PCAP… {count}/{total or '?'}")

        handle = parse_pcap(temp_file_path, on_progress=_on_progress)
        parsed_df = handle.as_dataframe()

        progress.progress(1.0, text="Tagging flows…")

        rules_path = Path(__file__).resolve().parent / "heuristics" / "rules.yaml"
        engine = HeuristicEngine(str(rules_path))
        df = engine.tag_flows(parsed_df)
        summary_df = generate_summary_df(df)
        progress.empty()
    except Exception as exc:
        progress.empty()
        st.error(f"Error during analysis: {exc}")
        df = None
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

if df is not None and not df.empty:
    output_area.dataframe(df)
    with st.expander("Preview Summary Report"):
        st.dataframe(summary_df, use_container_width=True)
else:
    if uploaded_file is None: # From Codex branch
        output_area.write("Upload a PCAP file to begin analysis.")
    elif not analysis_ran: # From Codex branch
        output_area.write("Click 'Parse & Analyze' to see results.")
    else: # From Codex branch
        output_area.write(
            "No analysis results to display. "
            "Check for errors above or try a different file."
        )

csv_data = b""
summary_csv = b""
pdf_data = b""
download_disabled = True
pdf_disabled = True
if df is not None and not df.empty:
    csv_data = df.to_csv(index=False).encode("utf-8")
    summary_csv = summary_df.to_csv(index=False).encode("utf-8")
    download_disabled = False
    try:
        pdf_data = generate_pdf_report(df)
        pdf_disabled = False
    except ImportError:
        st.warning("ReportLab not installed - PDF export disabled")

st.download_button(
    "⬇️  Download Full CSV",
    csv_data,
    file_name="pcap_full.csv",
    mime="text/csv",
    disabled=download_disabled,
)
st.download_button(
    "⬇️  Download Summary CSV",
    summary_csv,
    file_name="pcap_summary.csv",
    mime="text/csv",
    disabled=download_disabled,
)
st.download_button(
    "Download PDF Report",
    pdf_data,
    file_name="report.pdf",
    disabled=pdf_disabled,
)

# Removed the duplicated block from phase4-tests that was just placeholders

if __name__ == "__main__":
    print("Run this GUI with:  streamlit run src/app.py")

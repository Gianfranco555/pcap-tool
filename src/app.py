"""
Phase 6 (Streamlit UI MVP)

Covered user stories US-1 & US-3

Remaining TODOs (hook parser, hook heuristic engine, export logic)
"""

import os
import tempfile
from pathlib import Path

import streamlit as st

from pcap_tool.parser import parse_pcap
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
analysis_ran = False

if uploaded_file and st.button("Parse & Analyze"):
    with st.spinner("Parsing…"):
        analysis_ran = True
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcapng"
            ) as tmp:
                tmp.write(uploaded_file.getvalue())
                temp_file_path = tmp.name

            parsed_df = parse_pcap(temp_file_path)

            rules_path = (
                Path(__file__).resolve().parent / "heuristics" / "rules.yaml"
            )
            engine = HeuristicEngine(str(rules_path))
            df = engine.tag_flows(parsed_df)
        except Exception as exc:
            st.error(f"Error parsing file: {exc}")
            df = None
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

if df is not None and not df.empty:
    output_area.dataframe(df)
else:
    if uploaded_file is None:
        output_area.write("Upload a PCAP file to begin analysis.")
    elif not analysis_ran:
        output_area.write("Click 'Parse & Analyze' to see results.")
    else:
        output_area.write(
            "No analysis results to display. "
            "Check for errors above or try a different file."
        )

csv_data = b""
download_disabled = True
if df is not None and not df.empty:
    csv_data = df.to_csv(index=False).encode("utf-8")
    download_disabled = False

st.download_button(
    "Download CSV Report",
    csv_data,
    file_name="report.csv",
    disabled=download_disabled,
)
st.download_button(
    "Download PDF Report",
    b"",
    file_name="report.pdf",
    disabled=True,
)

if __name__ == "__main__":
    print("Run this GUI with:  streamlit run src/app.py")

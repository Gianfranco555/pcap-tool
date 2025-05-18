"""
Phase 6 (Streamlit UI MVP)

Covered user stories US-1 & US-3

Remaining TODOs (hook parser, hook heuristic engine, export logic)
"""

import streamlit as st

# TODO: implement
from src.pcap_tool.parser import parse_pcap  # noqa: F401  # TODO: implement
from src.pcap_tool.heuristics.engine import (  # noqa: F401
    HeuristicEngine,  # TODO: implement
)

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

if uploaded_file and st.button("Parse & Analyze"):
    with st.spinner("Parsing…"):
        try:
            # df = parse_pcap(uploaded_file)
            # tagged_df = HeuristicEngine("rules.yaml").tag(df)
            # df = tagged_df
            pass
        except Exception as exc:
            st.error(f"Error parsing file: {exc}")
            df = None

if df is not None:
    output_area.dataframe(df)
else:
    output_area.write("Analysis results will appear here.")

st.download_button("Download CSV Report", b"", file_name="report.csv")
st.download_button("Download PDF Report", b"", file_name="report.pdf")

if __name__ == "__main__":
    print("Run this GUI with:  streamlit run src/app.py")

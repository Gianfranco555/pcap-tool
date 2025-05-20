"""
Phase 6 (Streamlit UI MVP)

Covered user stories US-1 & US-3

Remaining TODOs (hook parser, hook heuristic engine, export logic)
"""

import os
import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
import altair as alt

from pcap_tool.pipeline_app import run_analysis

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
metrics_output = None
tagged_flow_df = pd.DataFrame()
text_summary = ""
pdf_bytes = b""
analysis_ran = False

if uploaded_file and st.button("Parse & Analyze"):
    analysis_ran = True
    progress = st.progress(0, text="Processing PCAP…")
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.getvalue())
            temp_file_path = tmp.name

        rules_path = Path(__file__).resolve().parent / "heuristics" / "rules.yaml"
        metrics_output, tagged_flow_df, text_summary, pdf_bytes = run_analysis(Path(temp_file_path), rules_path)
        progress.progress(1.0, text="Analysis complete")
    except Exception as exc:
        progress.empty()
        st.error(f"Error during analysis: {exc}")
        metrics_output = None
        tagged_flow_df = pd.DataFrame()
        text_summary = ""
        pdf_bytes = b""
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
    progress.empty()

if metrics_output is not None:
    overview_tab, flows_tab, errors_tab, timeline_tab, ai_tab = st.tabs(
        ["Overview", "Flows", "Errors & Security", "Timeline", "AI Summary"]
    )

    with overview_tab:
        capture = metrics_output.get("capture_info", {})
        perf = metrics_output.get("performance_metrics", {})
        if capture:
            st.subheader("Capture Info")
            st.json(capture)
        if perf:
            st.subheader("Performance Metrics")
            st.json(perf)

        proto_counts = metrics_output.get("protocols", {})
        if proto_counts:
            proto_df = pd.DataFrame(
                {"protocol": list(proto_counts.keys()), "count": list(proto_counts.values())}
            )
            chart = (
                alt.Chart(proto_df)
                .mark_arc()
                .encode(theta="count", color="protocol")
            )
            st.altair_chart(chart, use_container_width=True)

        port_counts = metrics_output.get("top_ports", {})
        if port_counts:
            port_data = []
            for name, count in port_counts.items():
                if "_" in name:
                    proto, port = name.split("_", 1)
                else:
                    proto, port = "", name
                port_data.append({"port": port, "protocol": proto.upper(), "count": count})
            ports_df = pd.DataFrame(port_data)
            chart = (
                alt.Chart(ports_df)
                .mark_bar()
                .encode(x="port:N", y="count:Q", color="protocol:N")
            )
            st.altair_chart(chart, use_container_width=True)

    with flows_tab:
        st.dataframe(tagged_flow_df, use_container_width=True)
        if "sparkline_bytes_c2s" in tagged_flow_df.columns:
            st.caption("Sparkline columns represent per-second byte counts")

    with errors_tab:
        st.subheader("Error Summary")
        st.json(metrics_output.get("error_summary", {}))
        err_df = pd.DataFrame()
        required_cols = {
            "packet_error_reason",
            "flow_id",
            "total_bytes",
            "first_ts",
        }
        if not tagged_flow_df.empty and required_cols.issubset(tagged_flow_df.columns):
            err_df = (
                tagged_flow_df.dropna(subset=["packet_error_reason"])
                .groupby("packet_error_reason")
                .agg(
                    affected_flows=("flow_id", "nunique"),
                    total_bytes=("total_bytes", "sum"),
                    first_seen=("first_ts", "min"),
                )
                .reset_index()
            )
        st.subheader("Network Errors")
        st.dataframe(err_df, use_container_width=True)
        st.subheader("Security Findings")
        st.json(metrics_output.get("security_findings", {}))

    with timeline_tab:
        timeline = metrics_output.get("timeline_data", [])
        if timeline:
            tl_df = pd.DataFrame(timeline)
            area = (
                alt.Chart(tl_df)
                .mark_area(opacity=0.6)
                .encode(x="timestamp:Q", y="bytes:Q")
            )
            spikes = tl_df[tl_df.get("spike")]
            if not spikes.empty:
                rules = alt.Chart(spikes).mark_rule(color="red").encode(x="timestamp:Q")
                chart = area + rules
            else:
                chart = area
            st.altair_chart(chart, use_container_width=True)

    with ai_tab:
        st.markdown(text_summary)
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

# Removed the duplicated block from phase4-tests that was just placeholders

if __name__ == "__main__":
    print("Run this GUI with:  streamlit run src/app.py")

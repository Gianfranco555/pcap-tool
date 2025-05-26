from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from pcap_tool.analyze import ErrorSummarizer, SecurityAuditor
from pcap_tool.enrichment import Enricher
from pcap_tool.metrics.retransmission import categorize_retransmission_severity
from pcap_tool.utils import render_status_pill

from .charts import protocol_pie_chart, port_bar_chart, tls_version_bar_chart


error_summarizer = ErrorSummarizer()
security_auditor = SecurityAuditor(Enricher())


def display_overview(metrics_output: dict[str, Any]) -> None:
    """Render the overview tab contents."""
    capture = metrics_output.get("capture_info", {})
    perf = metrics_output.get("performance_metrics", {})
    if capture:
        st.subheader("Capture Info")
        st.json(capture)
    if perf:
        st.subheader("Performance Metrics")
        sev = categorize_retransmission_severity(
            perf.get("tcp_retransmission_ratio_percent", 0.0)
        )
        st.markdown(
            f"""
    <span class="status-pill" style="background:{sev['color']};">
        {sev['status']}
    </span>
    """,
            unsafe_allow_html=True,
        )
        if perf.get("rtt_limited_data"):
            st.markdown(
                "<span class='status-pill' style='background:#ffc107;color:black;'>Limited RTT data available</span>",
                unsafe_allow_html=True,
            )
        else:
            st.json(perf.get("tcp_rtt_ms", {}))
        st.write(
            "Retransmission Ratio: "
            f"{perf.get('tcp_retransmission_ratio_percent', 0.0):.2f}%"
        )

    proto_counts = metrics_output.get("protocols", {})
    if proto_counts:
        chart = protocol_pie_chart(proto_counts)
        with st.container():
            st.altair_chart(chart, use_container_width=True)

    port_counts = metrics_output.get("top_ports", {})
    if port_counts:
        chart = port_bar_chart(port_counts)
        with st.container():
            st.altair_chart(chart, use_container_width=True)

    tls_version_counts = metrics_output.get("tls_version_counts", {})
    if tls_version_counts:
        fig = tls_version_bar_chart(tls_version_counts)
        with st.container():
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No TLS traffic detected")

    err_summary = metrics_output.get("error_summary", {})
    err_count = error_summarizer.get_total_error_count(err_summary)
    sec_findings = metrics_output.get("security_findings", {})
    sec_count = security_auditor.get_total_security_issue_count(sec_findings)
    st.subheader("Errors & Security Overview")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(render_status_pill("errors", err_count, True), unsafe_allow_html=True)
    with col_b:
        st.markdown(
            render_status_pill("security issues", sec_count, True),
            unsafe_allow_html=True,
        )


def display_errors(metrics_output: dict[str, Any], tagged_flow_df: pd.DataFrame) -> None:
    """Render the errors & security tab."""
    summary = metrics_output.get("error_summary", {})
    error_rows = error_summarizer.get_error_details_for_dataframe(summary)
    st.subheader("Error Summary")
    if not error_rows:
        st.markdown("No errors detected")
    else:
        st.dataframe(pd.DataFrame(error_rows), use_container_width=True)

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
    if err_df.empty:
        st.markdown("No packet errors detected")
    else:
        st.dataframe(err_df, use_container_width=True)

    st.subheader("Security Findings")
    sec = metrics_output.get("security_findings", {})
    keys = [
        "plaintext_http_flows",
        "outdated_tls_version_counts",
        "self_signed_certificate_flows",
        "connections_to_unusual_countries",
    ]
    cols = st.columns(len(keys))
    for col, key in zip(cols, keys):
        val = sec.get(key, {})
        if key == "outdated_tls_version_counts":
            count = sum(int(v) for v in val.values()) if isinstance(val, dict) else 0
        elif key == "connections_to_unusual_countries":
            count = len(val) if isinstance(val, dict) else 0
        else:
            count = int(val or 0) if not isinstance(val, dict) else 0
        label = key.replace("_", " ").title()
        col.markdown(
            render_status_pill(label, count, True),
            unsafe_allow_html=True,
        )

    if st.session_state.get("debug_mode", False):
        with st.expander("Raw Security Data (Debug)"):
            st.json(sec)


def display_timeline(metrics_output: dict[str, Any]) -> None:
    """Render the timeline tab."""
    timeline = metrics_output.get("timeline_data", [])
    if not timeline:
        return
    tl_df = pd.DataFrame(timeline).rename(columns={"timestamp": "ts"})
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=tl_df["ts"],
            y=tl_df["bytes"],
            mode="lines",
            name="Bytes",
            fill="tozeroy",
            yaxis="y1",
        )
    )
    if tl_df["packets"].max() > 0:
        fig.add_trace(
            go.Scatter(
                x=tl_df["ts"],
                y=tl_df["packets"],
                mode="lines",
                name="Packets",
                yaxis="y2",
            )
        )
        fig.update_layout(yaxis2=dict(title="Packets", overlaying="y", side="right"))
    fig.update_layout(
        title="Traffic Timeline",
        yaxis=dict(title="Bytes"),
        hovermode="x unified",
    )
    with st.container():
        st.plotly_chart(fig, use_container_width=True)

from __future__ import annotations

from typing import Callable

import pandas as pd
import streamlit as st

from pcap_tool.heuristics import guess_l7_protocol
from pcap_tool.ui.components.charts import flow_outcome_chart


def display_flow_table(tagged_flow_df: pd.DataFrame, guess_protocol: Callable = guess_l7_protocol) -> None:
    """Render the flows tab with optional protocol filter."""
    flows_df = tagged_flow_df
    if "l7_protocol_guess" not in flows_df.columns and not flows_df.empty:
        flows_df = flows_df.copy()

        def _guess_row(row: pd.Series) -> str:
            data = {
                "protocol": row.get("protocol"),
                "destination_port": row.get("destination_port", row.get("dest_port", row.get("server_port"))),
                "source_port": row.get("source_port", row.get("src_port", row.get("client_port"))),
                "first_flight_packet_size": row.get("first_flight_packet_size", row.get("first_flight_bytes")),
            }
            return guess_protocol(data)

        flows_df["l7_protocol_guess"] = flows_df.apply(_guess_row, axis=1)

    options = flows_df.get("l7_protocol_guess", pd.Series(dtype=object))
    options = options.dropna().unique().tolist()
    sel = st.multiselect("Filter by L7 Protocol", options)
    if sel:
        flows_show = flows_df[flows_df["l7_protocol_guess"].isin(sel)]
    else:
        flows_show = flows_df

    st.dataframe(flows_show, use_container_width=True)
    if "sparkline_bytes_c2s" in flows_df.columns:
        st.caption("Sparkline columns represent per-second byte counts")

    if not tagged_flow_df.empty and {"protocol", "flow_outcome"}.issubset(tagged_flow_df.columns):
        chart_df = tagged_flow_df.groupby(["protocol", "flow_outcome"]).size().reset_index(name="count")
        fig = flow_outcome_chart(chart_df)
        with st.container():
            st.plotly_chart(fig, use_container_width=True)

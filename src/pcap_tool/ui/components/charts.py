from __future__ import annotations

from typing import Any, Dict

import altair as alt
import pandas as pd
import plotly.express as px


def protocol_pie_chart(proto_counts: Dict[str, int]) -> alt.Chart:
    proto_df = pd.DataFrame({"protocol": list(proto_counts.keys()), "count": list(proto_counts.values())})
    return alt.Chart(proto_df).mark_arc().encode(theta="count", color="protocol")


def port_bar_chart(port_counts: Dict[str, int]):
    port_data = []
    for name, count in port_counts.items():
        if "_" in name:
            proto, port = name.split("_", 1)
        else:
            proto, port = "", name
        port_data.append({"port": port, "protocol": proto.upper(), "count": count})
    ports_df = pd.DataFrame(port_data)
    return alt.Chart(ports_df).mark_bar().encode(x="port:N", y="count:Q", color="protocol:N")


def tls_version_bar_chart(version_counts: Dict[str, int]) -> px.Figure:
    tls_df = pd.DataFrame(version_counts.items(), columns=["version", "count"])
    return px.bar(tls_df, x="count", y="version", orientation="h", title="Observed TLS Versions")


def flow_outcome_chart(group_df: pd.DataFrame):
    return px.bar(
        group_df,
        x="protocol",
        y="count",
        color="flow_outcome",
        title="Flow Outcomes by Protocol",
        labels={"count": "Flow Count"},
    )

import numpy as np
import pandas as pd
from typing import Any, List


__all__ = ["get_tls_handshake_outcome"]


def get_tls_handshake_outcome(packets_df: pd.DataFrame) -> pd.DataFrame:
    """Return TLS handshake outcome per flow.

    Parameters
    ----------
    packets_df:
        DataFrame containing packet level fields including ``timestamp``,
        ``tls_handshake_type``, ``tls_alert_message_description``,
        ``tcp_flags_rst`` and an orientation column (``is_source_client`` or
        ``is_src_client``).

    Returns
    -------
    pandas.DataFrame
        DataFrame with ``flow_id`` mapped the same way as
        :func:`VectorisedHeuristicEngine._aggregate_flows` and columns
        ``tls_handshake_ok`` (boolean), ``first_alert_time`` and
        ``time_to_alert``.

    Raises
    ------
    ValueError
        If the orientation or ``timestamp`` columns are missing.
    """
    if packets_df.empty:
        return pd.DataFrame(
            columns=["flow_id", "tls_handshake_ok", "first_alert_time", "time_to_alert"]
        )

    df = packets_df.copy()
    orient_col = None
    if "is_source_client" in df.columns:
        orient_col = "is_source_client"
    elif "is_src_client" in df.columns:
        orient_col = "is_src_client"
    if orient_col is None:
        raise ValueError("is_source_client column required for TLS analysis")

    cols = ["client_ip", "server_ip", "client_port", "server_port", "protocol"]
    df["client_ip"] = np.where(df[orient_col], df["source_ip"], df["destination_ip"])
    df["server_ip"] = np.where(df[orient_col], df["destination_ip"], df["source_ip"])
    df["client_port"] = np.where(df[orient_col], df["source_port"], df["destination_port"])
    df["server_port"] = np.where(df[orient_col], df["destination_port"], df["source_port"])
    if "timestamp" not in df.columns:
        raise ValueError("timestamp column required for TLS analysis")

    groups = df.groupby(cols)
    index = groups.size().index
    flow_df = pd.DataFrame(list(index), columns=cols)
    flow_df = flow_df.reset_index(drop=True)
    flow_df["flow_id"] = flow_df.index

    client_mask = df[orient_col] == True
    server_mask = df[orient_col] == False

    ch_mask = client_mask & (df.get("tls_handshake_type") == "ClientHello")
    sh_mask = server_mask & (df.get("tls_handshake_type") == "ServerHello")

    first_ch = df[ch_mask].groupby(cols)["timestamp"].min()
    first_sh = df[sh_mask].groupby(cols)["timestamp"].min()

    alert_mask = df.get("tls_alert_message_description").notna() if "tls_alert_message_description" in df.columns else pd.Series(False, index=df.index)
    rst_mask = df.get("tcp_flags_rst", pd.Series(False, index=df.index)).fillna(False)
    alert_mask = alert_mask | rst_mask
    first_alert = df[alert_mask].groupby(cols)["timestamp"].min()

    flow_df["first_client_hello_time"] = first_ch.reindex(index).values
    flow_df["first_server_hello_time"] = first_sh.reindex(index).values
    flow_df["first_alert_time"] = first_alert.reindex(index).values

    flow_df["time_to_alert"] = flow_df["first_alert_time"] - flow_df["first_client_hello_time"]

    handshake_ok = (
        flow_df["first_client_hello_time"].notna()
        & flow_df["first_server_hello_time"].notna()
        & (
            flow_df["first_alert_time"].isna()
            | (flow_df["first_server_hello_time"] <= flow_df["first_alert_time"])
        )
        & (
            (flow_df["first_server_hello_time"] - flow_df["first_client_hello_time"]) <= 5
        )
    )
    flow_df["tls_handshake_ok"] = pd.NA
    mask_ch = flow_df["first_client_hello_time"].notna()
    flow_df.loc[mask_ch, "tls_handshake_ok"] = handshake_ok[mask_ch]

    return flow_df[["flow_id", "tls_handshake_ok", "first_alert_time", "time_to_alert"]]

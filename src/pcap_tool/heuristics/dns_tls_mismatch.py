from __future__ import annotations

import pandas as pd
from typing import List, Tuple, Dict, Any


def _pick_column(df: pd.DataFrame, names: List[str]) -> str | None:
    for name in names:
        if name in df.columns:
            return name
    return None


def detect_dns_sni_mismatch(flows: pd.DataFrame) -> pd.DataFrame:
    """Return flows where TLS destination IP not in previous DNS answers."""
    res_cols = ["flow_id", "flow_disposition", "flow_cause"]
    if flows.empty:
        return pd.DataFrame(columns=res_cols)

    src_col = _pick_column(flows, ["src_ip", "source_ip", "client_ip"])
    dst_col = _pick_column(flows, ["dest_ip", "destination_ip", "server_ip"])
    port_col = _pick_column(flows, ["dest_port", "destination_port", "server_port"])
    ts_col = _pick_column(flows, ["timestamp", "start_time", "first_syn_time"])
    sni_col = _pick_column(flows, ["sni", "server_name_indication"])
    query_col = "dns_query_name" if "dns_query_name" in flows.columns else None
    resp_col = "dns_response_addresses" if "dns_response_addresses" in flows.columns else None

    if not all([src_col, dst_col, port_col, ts_col, sni_col, query_col, resp_col, "flow_id" in flows.columns]):
        return pd.DataFrame(columns=res_cols)

    df = flows.copy()
    if pd.api.types.is_numeric_dtype(df[ts_col]):
        df[ts_col] = pd.to_datetime(df[ts_col], unit="s", errors="coerce")
    else:
        df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")

    dns_df = df[
        (df[port_col] == 53)
        & df[query_col].notna()
        & df[ts_col].notna()
        & df[src_col].notna()
    ][[src_col, query_col, ts_col, resp_col]]

    dns_df[resp_col] = dns_df[resp_col].apply(
        lambda v: [str(a) for a in v] if isinstance(v, list) else ([str(v)] if pd.notna(v) else [])
    )

    dns_map: Dict[Tuple[str, str], List[Tuple[pd.Timestamp, set[str]]]] = {}
    for r in dns_df.itertuples(index=False):
        key = (getattr(r, src_col), getattr(r, query_col))
        dns_map.setdefault(key, []).append((getattr(r, ts_col), set(getattr(r, resp_col))))

    mismatches: List[Dict[str, Any]] = []
    tls_df = df[
        (df[port_col] == 443)
        & df[sni_col].notna()
        & df[ts_col].notna()
    ]
    for row in tls_df.itertuples():
        key = (getattr(row, src_col), getattr(row, sni_col))
        entries = dns_map.get(key)
        if not entries:
            continue
        ts = getattr(row, ts_col)
        answers: set[str] = set()
        for dns_ts, addrs in entries:
            if pd.isna(dns_ts) or pd.isna(ts):
                continue
            diff = (ts - dns_ts).total_seconds()
            if 0 <= diff <= DNS_TLS_MAX_AGE_SECONDS: # Assumes DNS_TLS_MAX_AGE_SECONDS is defined
                answers.update(addrs)
        if answers and str(getattr(row, dst_col)) not in answers:
            mismatches.append(
                {
                    "flow_id": getattr(row, "flow_id"),
                    "flow_disposition": "Mis-routed",
                    "flow_cause": "DNS answer set doesn’t include TLS target",
                }
            )
    return pd.DataFrame(mismatches, columns=res_cols)

__all__ = ["detect_dns_sni_mismatch"]

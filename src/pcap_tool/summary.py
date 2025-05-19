from __future__ import annotations

from typing import Iterable, Optional, IO, Any
import pandas as pd
from pcap_tool.logging import get_logger

logger = get_logger(__name__)


_PRIORITY_ORDER = ["Blocked", "Degraded", "Allowed", "Unknown"]
_TYPE_ORDER = [
    "HTTPS",
    "TLS",
    "HTTP",
    "DNS",
    "SSH",
    "ICMP",
    "TCP",
    "UDP",
    "OTHER",
]


def _priority_pick(values: Iterable[str]) -> Optional[str]:
    seen = {str(v) for v in values if pd.notna(v)}
    for choice in _PRIORITY_ORDER:
        if choice in seen:
            return choice
    return next(iter(seen), None)


def _pick_primary_type(values: Iterable[str]) -> Optional[str]:
    seen = [str(v) for v in values if pd.notna(v)]
    for t in _TYPE_ORDER:
        if t in seen:
            return t
    return seen[0] if seen else None


def _first_non_null(series: pd.Series) -> Optional[str]:
    for val in series:
        if pd.notna(val):
            return val
    return None


def _join_unique(series: pd.Series) -> Optional[str]:
    unique: set[str] = set()
    for val in series.dropna():
        if isinstance(val, str):
            parts = [p.strip() for p in val.split(";") if p.strip()]
        elif isinstance(val, Iterable):
            parts = [str(p).strip() for p in val if str(p).strip()]
        else:
            parts = [str(val).strip()]
        unique.update(parts)
    return ";".join(sorted(unique)) if unique else None


def _latest_dns_match(group: pd.DataFrame, dest_ip: str) -> tuple[Optional[str], Optional[str]]:
    if "dns_query_name" not in group.columns:
        return None, None
    matches = []
    if "dns_response_addresses" in group.columns:
        for _, row in group.iterrows():
            addrs = row.get("dns_response_addresses")
            if pd.isna(addrs):
                continue
            if not isinstance(addrs, list):
                addrs = [a.strip() for a in str(addrs).split(",")]
            if dest_ip in [str(a) for a in addrs]:
                matches.append(row)
    if not matches:
        return _first_non_null(group.get("dns_query_name")), _first_non_null(group.get("dns_response_code"))
    latest = max(matches, key=lambda r: r["timestamp"])
    return latest.get("dns_query_name"), latest.get("dns_response_code")


_DEF_COLUMNS = [
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "protocol",
    "start_time",
    "end_time",
    "duration_ms",
    "pkts_c2s",
    "pkts_s2c",
    "pkts_total",
    "bytes_c2s",
    "bytes_s2c",
    "bytes_total",
    "flow_disposition",
    "primary_traffic_type_guess",
    "security_observations",
    "sni_hostname",
    "http_host",
    "http_path",
    "dns_query",
    "dns_response_code",
]


def generate_summary_df(full_df: pd.DataFrame) -> pd.DataFrame:
    """Return aggregated flow summary from packet- or flow-level DataFrame."""

    if full_df.empty:
        return pd.DataFrame(columns=_DEF_COLUMNS)

    df = full_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "is_src_client" not in df.columns:
        logger.warning("'is_src_client' column not found. Defaulting to pd.NA.")
        df["is_src_client"] = pd.NA

    length_col = "frame_len" if "frame_len" in df.columns else "packet_length"

    df["_src_ip"] = df.apply(
        lambda r: r["source_ip"]
        if pd.notna(r.get("is_src_client")) and bool(r.get("is_src_client"))
        else r["destination_ip"],
        axis=1,
    )
    df["_dest_ip"] = df.apply(
        lambda r: r["destination_ip"]
        if pd.notna(r.get("is_src_client")) and bool(r.get("is_src_client"))
        else r["source_ip"],
        axis=1,
    )
    df["_src_port"] = df.apply(
        lambda r: r["source_port"]
        if pd.notna(r.get("is_src_client")) and bool(r.get("is_src_client"))
        else r["destination_port"],
        axis=1,
    )
    df["_dest_port"] = df.apply(
        lambda r: r["destination_port"]
        if pd.notna(r.get("is_src_client")) and bool(r.get("is_src_client"))
        else r["source_port"],
        axis=1,
    )

    group_cols = ["_src_ip", "_dest_ip", "_src_port", "_dest_port", "protocol"]
    summaries = []
    for keys, group in df.groupby(group_cols):
        src_ip, dest_ip, src_port, dest_port, proto = keys
        start_time = group["timestamp"].min()
        end_time = group["timestamp"].max()
        duration_ms = (end_time - start_time).total_seconds() * 1000

        c2s_mask = group["is_src_client"].fillna(False) == True
        s2c_mask = group["is_src_client"].fillna(False) == False

        pkts_c2s = int(c2s_mask.sum())
        pkts_s2c = int(s2c_mask.sum())
        pkts_total = pkts_c2s + pkts_s2c

        bytes_c2s = group.loc[c2s_mask, length_col].fillna(0).sum()
        bytes_s2c = group.loc[s2c_mask, length_col].fillna(0).sum()
        bytes_total = bytes_c2s + bytes_s2c

        flow_disp = _priority_pick(group.get("flow_disposition"))
        primary_type = _pick_primary_type(group.get("traffic_type_guess"))

        obs_col = (
            "security_observations"
            if "security_observations" in group.columns
            else "security_observation"
            if "security_observation" in group.columns
            else None
        )
        obs = _join_unique(group[obs_col]) if obs_col else None

        sni_hostname = _first_non_null(group.get("sni"))
        http_host = _first_non_null(group.get("http_request_host_header"))
        http_path = _first_non_null(group.get("http_request_uri"))
        dns_q, dns_rcode = _latest_dns_match(group, dest_ip)

        summaries.append(
            [
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                start_time,
                end_time,
                duration_ms,
                pkts_c2s,
                pkts_s2c,
                pkts_total,
                bytes_c2s,
                bytes_s2c,
                bytes_total,
                flow_disp,
                primary_type,
                obs,
                sni_hostname,
                http_host,
                http_path,
                dns_q,
                dns_rcode,
            ]
        )

    result = pd.DataFrame(summaries, columns=_DEF_COLUMNS)
    return result.sort_values("start_time").reset_index(drop=True)


def export_summary_excel(summary_df: pd.DataFrame, path: str | IO[Any] = "summary.xlsx") -> None:
    """Write ``summary_df`` to an Excel file with a sheet per protocol.

    Parameters
    ----------
    summary_df:
        The DataFrame returned from :func:`generate_summary_df`.
    path:
        File path or file-like object to write the Excel workbook to.

    Raises
    ------
    ImportError
        If an Excel writer engine (``openpyxl`` or ``xlsxwriter``) is not available.
    """

    try:
        with pd.ExcelWriter(path) as writer:  # type: ignore[list-item]
            for proto, group in summary_df.groupby("protocol"):
                sheet = str(proto)[:31] if str(proto) else "UNKNOWN"
                group.to_excel(writer, sheet_name=sheet, index=False)
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "Excel export requires 'openpyxl' or 'xlsxwriter' to be installed"
        ) from exc

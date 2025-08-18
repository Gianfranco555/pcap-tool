"""Core data structures for parsed packet records."""

from __future__ import annotations

from dataclasses import MISSING, dataclass, field, fields
from datetime import datetime
from typing import Any, List, Optional, Union, get_args, get_origin, get_type_hints
import pandas as pd


def _safe_int(value: Any) -> Optional[int]:
    """Safely convert numbers that may contain commas to ``int``."""

    try:
        return int(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


@dataclass
class PcapRecord:
    frame_number: int = 0
    timestamp: float = 0.0
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""
    sni: str = ""
    raw_packet_summary: str = ""
    source_mac: str = ""
    destination_mac: str = ""
    protocol_l3: str = ""
    packet_length: int = 0
    ip_ttl: int = 0
    ip_flags_df: bool = False
    ip_id: str = ""
    dscp_value: int = 0
    tcp_flags_syn: bool = False
    tcp_flags_ack: bool = False
    tcp_flags_fin: bool = False
    tcp_flags_rst: bool = False
    tcp_flags_psh: bool = False
    tcp_flags_urg: bool = False
    tcp_flags_ece: bool = False
    tcp_flags_cwr: bool = False
    tcp_sequence_number: int = 0
    tcp_acknowledgment_number: int = 0
    tcp_window_size: int = 0
    tcp_options_mss: int = 0
    tcp_options_sack_permitted: bool = False
    tcp_options_window_scale: int = 0
    tcp_stream_index: int = 0
    is_src_client: bool = False
    is_source_client: bool = False
    tcp_analysis_retransmission_flags: List[str] = field(default_factory=list)
    tcp_analysis_duplicate_ack_flags: List[str] = field(default_factory=list)
    tcp_analysis_out_of_order_flags: List[str] = field(default_factory=list)
    tcp_analysis_window_flags: List[str] = field(default_factory=list)
    dup_ack_num: int = 0
    adv_window: int = 0
    tcp_rtt_ms: float = 0.0
    tls_handshake_type: str = ""
    tls_handshake_version: str = ""
    tls_record_version: str = ""
    tls_cipher_suites_offered: List[str] = field(default_factory=list)
    tls_cipher_suite_selected: str = ""
    tls_alert_message_description: str = ""
    tls_alert_level: str = ""
    tls_effective_version: str = ""
    # ── TLS certificate metadata ─────────────────────────────────────────
    tls_cert_subject_cn: str = ""
    tls_cert_san_dns: List[str] = field(default_factory=list)  # list of DNS SANs
    tls_cert_san_ip: List[str] = field(default_factory=list)   # list of IP SANs
    tls_cert_issuer_cn: str = ""
    tls_cert_serial_number: str = ""
    tls_cert_not_before: Optional[datetime] = None
    tls_cert_not_after: Optional[datetime] = None
    tls_cert_sig_alg: str = ""
    tls_cert_key_length: int = 0
    tls_cert_is_self_signed: bool = False
    dns_query_name: str = ""
    dns_query_type: str = ""
    dns_response_code: str = ""
    dns_response_addresses: List[str] = field(default_factory=list)
    dns_response_cname_target: str = ""
    http_request_method: str = ""
    http_request_uri: str = ""
    http_request_host_header: str = ""
    http_response_code: int = 0
    http_response_location_header: str = ""
    http_x_forwarded_for_header: str = ""
    icmp_type: int = 0
    icmp_code: int = 0
    icmp_fragmentation_needed_original_mtu: int = 0
    arp_opcode: int = 0
    arp_sender_mac: str = ""
    arp_sender_ip: str = ""
    arp_target_mac: str = ""
    arp_target_ip: str = ""
    dhcp_message_type: str = ""
    gre_protocol: str = ""
    esp_spi: str = ""
    quic_initial_packet_present: bool = False
    is_quic: bool = False
    is_zscaler_ip: bool = False
    is_zpa_synthetic_ip: bool = False
    ssl_inspection_active: bool = False
    zscaler_policy_block_type: str = ""

    @classmethod
    def from_parser_row(cls, row: dict[str, Any]) -> "PcapRecord":
        """Create a :class:`PcapRecord` from a parser ``row``.

        Any missing, ``None`` or NaN values are replaced with the field's
        default and coerced to the correct type.  This prevents ``NaN`` values
        from propagating into numeric operations.
        """

        data: dict[str, Any] = {}
        type_hints = get_type_hints(cls)
        for f in fields(cls):
            hinted = type_hints.get(f.name, f.type)
            origin = get_origin(hinted)
            args = get_args(hinted)
            base_type = hinted
            if origin in (list, List):
                base_type = list
            elif origin is Union and type(None) in args:
                non_none = [a for a in args if a is not type(None)]
                if non_none:
                    base_type = non_none[0]

            if f.default is not MISSING:
                default = f.default
            elif f.default_factory is not MISSING:  # type: ignore[attr-defined]
                default = f.default_factory()  # type: ignore[misc]
            elif base_type is int:
                default = 0
            elif base_type is float:
                default = 0.0
            elif base_type is bool:
                default = False
            elif base_type is str:
                default = ""
            elif base_type is list:
                default = []
            else:
                default = None

            value = row.get(f.name, default)

            if value is None:
                value = default
            else:
                # Only check for NaN/NA for types where it makes sense
                try:
                    if isinstance(value, (float, str)) or (
                        hasattr(value, "__array__") or hasattr(value, "__float__")
                    ):
                        if pd.isna(value):  # handles NaN and pandas.NA
                            value = default
                except (TypeError, ValueError):
                    # pd.isna may raise for unsupported types; treat as not NA
                    pass

            if base_type in (int,):
                coerced = _safe_int(value)
                value = coerced if coerced is not None else default
            elif base_type is float:
                try:
                    value = float(value)
                except (TypeError, ValueError):
                    value = default
            elif base_type is bool:
                if isinstance(value, str):
                    value = value.strip().lower() in {"1", "true", "yes"}
                else:
                    value = bool(value)
            elif base_type is str:
                value = "" if value is None else str(value)
            elif base_type is list:
                if value is None:
                    value = []
                elif not isinstance(value, list):
                    value = [value]
            data[f.name] = value

        return cls(**data)

    def __post_init__(self) -> None:
        """Normalize key fields for consistency."""

        try:
            self.frame_number = int(self.frame_number)
        except (TypeError, ValueError):
            self.frame_number = 0
        try:
            self.timestamp = float(self.timestamp)
        except (TypeError, ValueError):
            self.timestamp = 0.0

        if isinstance(self.source_port, str):
            self.source_port = _safe_int(self.source_port)
        elif isinstance(self.source_port, float) and pd.isna(self.source_port):
            self.source_port = 0
        if isinstance(self.destination_port, str):
            self.destination_port = _safe_int(self.destination_port)
        elif isinstance(self.destination_port, float) and pd.isna(self.destination_port):
            self.destination_port = 0

        if isinstance(self.tcp_stream_index, str):
            self.tcp_stream_index = _safe_int(self.tcp_stream_index)
        elif isinstance(self.tcp_stream_index, float) and pd.isna(self.tcp_stream_index):
            self.tcp_stream_index = 0

    def __str__(self) -> str:
        # ... (previous __str__ content, potentially updated for new fields) ...
        final_chunk_info: List[str] = []
        if self.gre_protocol:
            final_chunk_info.append(f"GRE_Proto:{self.gre_protocol}")
        if self.esp_spi:
            final_chunk_info.append(f"ESP_SPI:{self.esp_spi}")
        if self.quic_initial_packet_present is not None:
            final_chunk_info.append(f"QUIC_Initial:{self.quic_initial_packet_present}")
        if self.is_quic is not None:
            final_chunk_info.append(f"IsQUIC:{self.is_quic}")
        if self.is_zscaler_ip is not None:
            final_chunk_info.append(f"ZscalerIP:{self.is_zscaler_ip}")
        if self.is_zpa_synthetic_ip is not None:
            final_chunk_info.append(f"ZPA_SynthIP:{self.is_zpa_synthetic_ip}")
        if self.is_src_client is not None:
            final_chunk_info.append(f"SrcIsClient:{self.is_src_client}")
        if self.ssl_inspection_active is not None:
            final_chunk_info.append(f"SSL_Inspect:{self.ssl_inspection_active}")
        if self.zscaler_policy_block_type:
            final_chunk_info.append(f"ZS_Block:{self.zscaler_policy_block_type}")
        final_chunk_str = ", ".join(final_chunk_info)

        return (
            f"Frame: {self.frame_number}, Time: {self.timestamp:.6f}, "
            f"IP: {self.source_ip or 'N/A'}:{self.source_port or 'N/A'} -> "
            f"{self.destination_ip or 'N/A'}:{self.destination_port or 'N/A'}, "
            f"L4_Proto: {self.protocol or 'N/A'}, "
            f"Extra: [{final_chunk_str if final_chunk_str else 'N/A'}], SNI: {self.sni if self.sni else 'N/A'}"
        )


class ParsedHandle:
    """Represents parsed flows stored in memory or on disk."""

    def __init__(self, backend: str, location: Any) -> None:
        self.backend = backend
        self.location = location

    def as_dataframe(self, limit: int | None = None) -> "pd.DataFrame":
        import pandas as pd

        if self.backend == "memory":
            df: pd.DataFrame = self.location
            return df.head(limit) if limit is not None else df
        if self.backend == "duckdb":
            import duckdb

            conn = duckdb.connect(self.location)
            query = "SELECT * FROM flows"
            if limit is not None:
                query += f" LIMIT {limit}"
            return conn.execute(query).df()
        if self.backend == "arrow":
            import pyarrow.dataset as ds

            dataset = ds.dataset(self.location, format="ipc")
            table = dataset.head(limit) if limit is not None else dataset.to_table()
            return table.to_pandas()
        raise ValueError(f"Unsupported backend: {self.backend}")

    def count(self) -> int:
        if self.backend == "memory":
            return len(self.location)
        if self.backend == "duckdb":
            import duckdb

            conn = duckdb.connect(self.location)
            return conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        if self.backend == "arrow":
            import pyarrow.dataset as ds

            dataset = ds.dataset(self.location, format="ipc")
            return dataset.count_rows()
        raise ValueError(f"Unsupported backend: {self.backend}")

    def to_parquet(self, path: str) -> None:
        if self.backend == "memory":
            self.location.to_parquet(path, index=False)
            return
        if self.backend == "duckdb":
            import duckdb

            conn = duckdb.connect(self.location)
            conn.execute(f"COPY flows TO '{path}' (FORMAT 'PARQUET')")
            return
        if self.backend == "arrow":
            import pyarrow.dataset as ds
            import pyarrow.parquet as pq

            dataset = ds.dataset(self.location, format="ipc")
            pq.write_table(dataset.to_table(), path)
            return
        raise ValueError(f"Unsupported backend: {self.backend}")


__all__ = ["PcapRecord", "ParsedHandle"]

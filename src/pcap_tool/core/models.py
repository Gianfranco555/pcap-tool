"""Core data structures for parsed packet records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional
import pandas as pd


def _safe_int(value: Any) -> Optional[int]:
    """Safely convert numbers that may contain commas to ``int``."""

    try:
        return int(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


@dataclass
class PcapRecord:
    frame_number: int
    timestamp: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    sni: Optional[str] = None
    raw_packet_summary: Optional[str] = None
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    protocol_l3: Optional[str] = None
    packet_length: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_flags_df: Optional[bool] = None
    ip_id: Optional[str] = None
    dscp_value: Optional[int] = None
    tcp_flags_syn: Optional[bool] = None
    tcp_flags_ack: Optional[bool] = None
    tcp_flags_fin: Optional[bool] = None
    tcp_flags_rst: Optional[bool] = None
    tcp_flags_psh: Optional[bool] = None
    tcp_flags_urg: Optional[bool] = None
    tcp_flags_ece: Optional[bool] = None
    tcp_flags_cwr: Optional[bool] = None
    tcp_sequence_number: Optional[int] = None
    tcp_acknowledgment_number: Optional[int] = None
    tcp_window_size: Optional[int] = None
    tcp_options_mss: Optional[int] = None
    tcp_options_sack_permitted: Optional[bool] = None
    tcp_options_window_scale: Optional[int] = None
    tcp_stream_index: Optional[int] = None
    is_src_client: Optional[bool] = None
    is_source_client: Optional[bool] = None
    tcp_analysis_retransmission_flags: List[str] = field(default_factory=list)
    tcp_analysis_duplicate_ack_flags: List[str] = field(default_factory=list)
    tcp_analysis_out_of_order_flags: List[str] = field(default_factory=list)
    tcp_analysis_window_flags: List[str] = field(default_factory=list)
    dup_ack_num: Optional[int] = None
    adv_window: Optional[int] = None
    tcp_rtt_ms: Optional[float] = None
    tls_handshake_type: Optional[str] = None
    tls_handshake_version: Optional[str] = None
    tls_record_version: Optional[str] = None
    tls_cipher_suites_offered: Optional[List[str]] = None
    tls_cipher_suite_selected: Optional[str] = None
    tls_alert_message_description: Optional[str] = None
    tls_alert_level: Optional[str] = None
    tls_effective_version: Optional[str] = None
    # ── TLS certificate metadata ─────────────────────────────────────────
    tls_cert_subject_cn: Optional[str] = None
    tls_cert_san_dns: Optional[List[str]] = None  # list of DNS SANs
    tls_cert_san_ip: Optional[List[str]] = None   # list of IP SANs
    tls_cert_issuer_cn: Optional[str] = None
    tls_cert_serial_number: Optional[str] = None
    tls_cert_not_before: Optional[datetime] = None
    tls_cert_not_after: Optional[datetime] = None
    tls_cert_sig_alg: Optional[str] = None
    tls_cert_key_length: Optional[int] = None
    tls_cert_is_self_signed: Optional[bool] = None
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_response_code: Optional[str] = None
    dns_response_addresses: Optional[List[str]] = None
    dns_response_cname_target: Optional[str] = None
    http_request_method: Optional[str] = None
    http_request_uri: Optional[str] = None
    http_request_host_header: Optional[str] = None
    http_response_code: Optional[int] = None
    http_response_location_header: Optional[str] = None
    http_x_forwarded_for_header: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    icmp_fragmentation_needed_original_mtu: Optional[int] = None
    arp_opcode: Optional[int] = None
    arp_sender_mac: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    dhcp_message_type: Optional[str] = None
    gre_protocol: Optional[str] = None
    esp_spi: Optional[str] = None
    quic_initial_packet_present: Optional[bool] = None
    is_quic: Optional[bool] = None
    is_zscaler_ip: Optional[bool] = None
    is_zpa_synthetic_ip: Optional[bool] = None
    ssl_inspection_active: Optional[bool] = None
    zscaler_policy_block_type: Optional[str] = None

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
        if isinstance(self.destination_port, str):
            self.destination_port = _safe_int(self.destination_port)

        if isinstance(self.tcp_stream_index, str):
            self.tcp_stream_index = _safe_int(self.tcp_stream_index)

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

"""Core data structures for parsed packet records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional
import pandas as pd
import math


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
    tls_cert_san_dns: List[str] = field(default_factory=list)
    tls_cert_san_ip: List[str] = field(default_factory=list)
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
    def from_parser_row(cls, row: Any) -> "PcapRecord":
        """
        Factory method to create a PcapRecord from a parser row,
        safely handling missing data, NaNs, and incorrect types.
        """
        def to_int(value: Any, default: int = 0) -> int:
            if value is None or (isinstance(value, float) and pd.isna(value)):
                return default
            try:
                return int(str(value).replace(",", ""))
            except (ValueError, TypeError):
                return default

        def to_float(value: Any) -> float:
            if value is None or (isinstance(value, float) and pd.isna(value)):
                return 0.0
            try:
                return float(value)
            except (ValueError, TypeError):
                return 0.0

        def to_str(value: Any) -> str:
            if value is None or (isinstance(value, float) and pd.isna(value)):
                return ""
            return str(value)

        def to_bool(value: Any) -> bool:
            if value is None or (isinstance(value, float) and pd.isna(value)):
                return False
            if isinstance(value, str):
                return value.lower().strip() in ('true', '1', 't', 'y', 'yes')
            return bool(value)

        def to_list(value: Any) -> list:
            if value is None or (isinstance(value, float) and pd.isna(value)):
                return []
            if isinstance(value, (list, set, tuple)):
                return list(value)
            return []

        def to_datetime(value: Any) -> Optional[datetime]:
            if value is None or (isinstance(value, float) and pd.isna(value)):
                return None
            try:
                # pyshark can return datetime strings with weird timezones like 'UTC-5'
                # which pandas struggles with. We can strip them for now.
                if isinstance(value, str) and ('UTC' in value or 'GMT' in value):
                    value = value.split(" (")[0]
                dt = pd.to_datetime(value)
                if pd.isna(dt):
                    return None
                return dt
            except (ValueError, TypeError):
                return None

        return cls(
            frame_number=to_int(getattr(row, 'frame_number', 0)),
            timestamp=to_float(getattr(row, 'timestamp', 0.0)),
            source_ip=to_str(getattr(row, 'source_ip', "")),
            destination_ip=to_str(getattr(row, 'destination_ip', "")),
            source_port=to_int(getattr(row, 'source_port', 0)),
            destination_port=to_int(getattr(row, 'destination_port', 0)),
            protocol=to_str(getattr(row, 'protocol', "")),
            sni=to_str(getattr(row, 'sni', "")),
            raw_packet_summary=to_str(getattr(row, 'raw_packet_summary', "")),
            source_mac=to_str(getattr(row, 'source_mac', "")),
            destination_mac=to_str(getattr(row, 'destination_mac', "")),
            protocol_l3=to_str(getattr(row, 'protocol_l3', "")),
            packet_length=to_int(getattr(row, 'packet_length', 0)),
            ip_ttl=to_int(getattr(row, 'ip_ttl', 0)),
            ip_flags_df=to_bool(getattr(row, 'ip_flags_df', False)),
            ip_id=to_str(getattr(row, 'ip_id', "")),
            dscp_value=to_int(getattr(row, 'dscp_value', 0)),
            tcp_flags_syn=to_bool(getattr(row, 'tcp_flags_syn', False)),
            tcp_flags_ack=to_bool(getattr(row, 'tcp_flags_ack', False)),
            tcp_flags_fin=to_bool(getattr(row, 'tcp_flags_fin', False)),
            tcp_flags_rst=to_bool(getattr(row, 'tcp_flags_rst', False)),
            tcp_flags_psh=to_bool(getattr(row, 'tcp_flags_psh', False)),
            tcp_flags_urg=to_bool(getattr(row, 'tcp_flags_urg', False)),
            tcp_flags_ece=to_bool(getattr(row, 'tcp_flags_ece', False)),
            tcp_flags_cwr=to_bool(getattr(row, 'tcp_flags_cwr', False)),
            tcp_sequence_number=to_int(getattr(row, 'tcp_sequence_number', 0)),
            tcp_acknowledgment_number=to_int(getattr(row, 'tcp_acknowledgment_number', 0)),
            tcp_window_size=to_int(getattr(row, 'tcp_window_size', 0)),
            tcp_options_mss=to_int(getattr(row, 'tcp_options_mss', 0)),
            tcp_options_sack_permitted=to_bool(getattr(row, 'tcp_options_sack_permitted', False)),
            tcp_options_window_scale=to_int(getattr(row, 'tcp_options_window_scale', 0)),
            tcp_stream_index=to_int(getattr(row, 'tcp_stream_index', None), default=-1),
            is_src_client=to_bool(getattr(row, 'is_src_client', False)),
            is_source_client=to_bool(getattr(row, 'is_source_client', False)),
            tcp_analysis_retransmission_flags=to_list(getattr(row, 'tcp_analysis_retransmission_flags', [])),
            tcp_analysis_duplicate_ack_flags=to_list(getattr(row, 'tcp_analysis_duplicate_ack_flags', [])),
            tcp_analysis_out_of_order_flags=to_list(getattr(row, 'tcp_analysis_out_of_order_flags', [])),
            tcp_analysis_window_flags=to_list(getattr(row, 'tcp_analysis_window_flags', [])),
            dup_ack_num=to_int(getattr(row, 'dup_ack_num', 0)),
            adv_window=to_int(getattr(row, 'adv_window', 0)),
            tcp_rtt_ms=to_float(getattr(row, 'tcp_rtt_ms', 0.0)),
            tls_handshake_type=to_str(getattr(row, 'tls_handshake_type', "")),
            tls_handshake_version=to_str(getattr(row, 'tls_handshake_version', "")),
            tls_record_version=to_str(getattr(row, 'tls_record_version', "")),
            tls_cipher_suites_offered=to_list(getattr(row, 'tls_cipher_suites_offered', [])),
            tls_cipher_suite_selected=to_str(getattr(row, 'tls_cipher_suite_selected', "")),
            tls_alert_message_description=to_str(getattr(row, 'tls_alert_message_description', "")),
            tls_alert_level=to_str(getattr(row, 'tls_alert_level', "")),
            tls_effective_version=to_str(getattr(row, 'tls_effective_version', "")),
            tls_cert_subject_cn=to_str(getattr(row, 'tls_cert_subject_cn', "")),
            tls_cert_san_dns=to_list(getattr(row, 'tls_cert_san_dns', [])),
            tls_cert_san_ip=to_list(getattr(row, 'tls_cert_san_ip', [])),
            tls_cert_issuer_cn=to_str(getattr(row, 'tls_cert_issuer_cn', "")),
            tls_cert_serial_number=to_str(getattr(row, 'tls_cert_serial_number', "")),
            tls_cert_not_before=to_datetime(getattr(row, 'tls_cert_not_before', None)),
            tls_cert_not_after=to_datetime(getattr(row, 'tls_cert_not_after', None)),
            tls_cert_sig_alg=to_str(getattr(row, 'tls_cert_sig_alg', "")),
            tls_cert_key_length=to_int(getattr(row, 'tls_cert_key_length', 0)),
            tls_cert_is_self_signed=to_bool(getattr(row, 'tls_cert_is_self_signed', False)),
            dns_query_name=to_str(getattr(row, 'dns_query_name', "")),
            dns_query_type=to_str(getattr(row, 'dns_query_type', "")),
            dns_response_code=to_str(getattr(row, 'dns_response_code', "")),
            dns_response_addresses=to_list(getattr(row, 'dns_response_addresses', [])),
            dns_response_cname_target=to_str(getattr(row, 'dns_response_cname_target', "")),
            http_request_method=to_str(getattr(row, 'http_request_method', "")),
            http_request_uri=to_str(getattr(row, 'http_request_uri', "")),
            http_request_host_header=to_str(getattr(row, 'http_request_host_header', "")),
            http_response_code=to_int(getattr(row, 'http_response_code', 0)),
            http_response_location_header=to_str(getattr(row, 'http_response_location_header', "")),
            http_x_forwarded_for_header=to_str(getattr(row, 'http_x_forwarded_for_header', "")),
            icmp_type=to_int(getattr(row, 'icmp_type', 0)),
            icmp_code=to_int(getattr(row, 'icmp_code', 0)),
            icmp_fragmentation_needed_original_mtu=to_int(getattr(row, 'icmp_fragmentation_needed_original_mtu', 0)),
            arp_opcode=to_int(getattr(row, 'arp_opcode', 0)),
            arp_sender_mac=to_str(getattr(row, 'arp_sender_mac', "")),
            arp_sender_ip=to_str(getattr(row, 'arp_sender_ip', "")),
            arp_target_mac=to_str(getattr(row, 'arp_target_mac', "")),
            arp_target_ip=to_str(getattr(row, 'arp_target_ip', "")),
            dhcp_message_type=to_str(getattr(row, 'dhcp_message_type', "")),
            gre_protocol=to_str(getattr(row, 'gre_protocol', "")),
            esp_spi=to_str(getattr(row, 'esp_spi', "")),
            quic_initial_packet_present=to_bool(getattr(row, 'quic_initial_packet_present', False)),
            is_quic=to_bool(getattr(row, 'is_quic', False)),
            is_zscaler_ip=to_bool(getattr(row, 'is_zscaler_ip', False)),
            is_zpa_synthetic_ip=to_bool(getattr(row, 'is_zpa_synthetic_ip', False)),
            ssl_inspection_active=to_bool(getattr(row, 'ssl_inspection_active', False)),
            zscaler_policy_block_type=to_str(getattr(row, 'zscaler_policy_block_type', "")),
        )

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

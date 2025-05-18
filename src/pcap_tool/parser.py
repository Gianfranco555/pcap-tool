# src/pcap_tool/parser.py
from dataclasses import dataclass, asdict
from typing import Optional, Generator, List, Any # Added Any
import logging
import pandas as pd
from pathlib import Path
import ipaddress

logger = logging.getLogger(__name__)

_USE_PYSHARK = False
_USE_PCAPKIT = False

try:
    import pyshark
    _USE_PYSHARK = True
    logger.info("PyShark library found and will be used as the primary parser.")
except ImportError:
    logger.warning("PyShark library not found. Attempting PCAPKit.")

if not _USE_PYSHARK:
    try:
        from pcapkit import extract as pcapkit_extract
        # ... other pcapkit imports from original ...
        _USE_PCAPKIT = True
        logger.info("PCAPKit library found and will be used as a fallback parser.")
    except ImportError:
        logger.warning("PCAPKit library not found.")

if not _USE_PYSHARK and not _USE_PCAPKIT:
    logger.error("Neither PyShark nor PCAPKit is available. PCAP parsing will not function.")

# --- Helper Dictionaries (TLS, DNS, DHCP from previous chunks) ---
TLS_HANDSHAKE_TYPE_MAP = { '0': "HelloRequest", '1': "ClientHello", '2': "ServerHello", '4': "NewSessionTicket", '5': "EndOfEarlyData", '8': "EncryptedExtensions", '11': "Certificate", '12': "ServerKeyExchange", '13': "CertificateRequest", '14': "ServerHelloDone", '15': "CertificateVerify", '16': "ClientKeyExchange", '20': "Finished", '24': "CertificateStatus", '25': "KeyUpdate",}
TLS_VERSION_MAP = {"0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",}
TLS_ALERT_LEVEL_MAP = {'1': "warning", '2': "fatal",}
TLS_ALERT_DESCRIPTION_MAP = {'0': "close_notify", '10': "unexpected_message", '20': "bad_record_mac", '21': "decryption_failed_RESERVED", '22': "record_overflow", '30': "decompression_failure", '40': "handshake_failure", '41': "no_certificate_RESERVED", '42': "bad_certificate", '43': "unsupported_certificate", '44': "certificate_revoked", '45': "certificate_expired", '46': "certificate_unknown", '47': "illegal_parameter", '48': "unknown_ca", '49': "access_denied", '50': "decode_error", '51': "decrypt_error", '60': "export_restriction_RESERVED", '70': "protocol_version", '71': "insufficient_security", '80': "internal_error", '86': "inappropriate_fallback", '90': "user_canceled", '100': "no_renegotiation_RESERVED", '110': "missing_extension", '111': "unsupported_extension", '112': "unrecognized_name", '113': "bad_certificate_status_response", '114': "unknown_psk_identity", '115': "certificate_required", '116': "no_application_protocol",}
DNS_QUERY_TYPE_MAP = {'1': "A", '2': "NS", '5': "CNAME", '6': "SOA", '12': "PTR", '15': "MX", '16': "TXT", '28': "AAAA", '33': "SRV", '43': "DS", '46': "RRSIG", '47': "NSEC", '48': "DNSKEY", '255': "ANY", '257': "CAA",}
DNS_RCODE_MAP = {'0': "NOERROR", '1': "FORMERR", '2': "SERVFAIL", '3': "NXDOMAIN", '4': "NOTIMP", '5': "REFUSED",}
DHCP_MESSAGE_TYPE_MAP = {'1': "Discover", '2': "Offer", '3': "Request", '4': "Decline", '5': "Ack", '6': "Nak", '7': "Release", '8': "Inform",}

ZSCALER_EXAMPLE_IP_RANGES = [
    ipaddress.ip_network("104.129.192.0/20"),
    ipaddress.ip_network("165.225.0.0/17"),
]
ZPA_SYNTHETIC_IP_RANGE = ipaddress.ip_network("100.64.0.0/10")

@dataclass
class PcapRecord:
    frame_number: int
    timestamp: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None; destination_port: Optional[int] = None
    protocol: Optional[str] = None; sni: Optional[str] = None; raw_packet_summary: Optional[str] = None
    source_mac: Optional[str] = None; destination_mac: Optional[str] = None
    protocol_l3: Optional[str] = None; packet_length: Optional[int] = None
    ip_ttl: Optional[int] = None; ip_flags_df: Optional[bool] = None; ip_id: Optional[str] = None; dscp_value: Optional[int] = None
    tcp_flags_syn: Optional[bool] = None; tcp_flags_ack: Optional[bool] = None; tcp_flags_fin: Optional[bool] = None
    tcp_flags_rst: Optional[bool] = None; tcp_flags_psh: Optional[bool] = None; tcp_flags_urg: Optional[bool] = None
    tcp_flags_ece: Optional[bool] = None; tcp_flags_cwr: Optional[bool] = None
    tcp_sequence_number: Optional[int] = None; tcp_acknowledgment_number: Optional[int] = None
    tcp_window_size: Optional[int] = None; tcp_options_mss: Optional[int] = None
    tcp_options_sack_permitted: Optional[bool] = None; tcp_options_window_scale: Optional[int] = None
    tcp_stream_index: Optional[int] = None; tcp_analysis_retransmission: Optional[bool] = None
    tcp_analysis_duplicate_ack: Optional[bool] = None; tcp_analysis_out_of_order: Optional[bool] = None
    tcp_analysis_zero_window: Optional[bool] = None
    tls_handshake_type: Optional[str] = None; tls_handshake_version: Optional[str] = None
    tls_record_version: Optional[str] = None; tls_cipher_suites_offered: Optional[List[str]] = None
    tls_cipher_suite_selected: Optional[str] = None; tls_alert_message_description: Optional[str] = None
    tls_alert_level: Optional[str] = None
    dns_query_name: Optional[str] = None; dns_query_type: Optional[str] = None
    dns_response_code: Optional[str] = None; dns_response_addresses: Optional[List[str]] = None
    dns_response_cname_target: Optional[str] = None
    http_request_method: Optional[str] = None; http_request_uri: Optional[str] = None
    http_request_host_header: Optional[str] = None; http_response_code: Optional[int] = None
    http_response_location_header: Optional[str] = None; http_x_forwarded_for_header: Optional[str] = None
    icmp_type: Optional[int] = None; icmp_code: Optional[int] = None
    icmp_fragmentation_needed_original_mtu: Optional[int] = None
    arp_opcode: Optional[int] = None; arp_sender_mac: Optional[str] = None
    arp_sender_ip: Optional[str] = None; arp_target_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None; dhcp_message_type: Optional[str] = None
    gre_protocol: Optional[str] = None
    esp_spi: Optional[str] = None
    quic_initial_packet_present: Optional[bool] = None
    is_zscaler_ip: Optional[bool] = None
    is_zpa_synthetic_ip: Optional[bool] = None
    ssl_inspection_active: Optional[bool] = None
    zscaler_policy_block_type: Optional[str] = None

    def __str__(self):
        # ... (previous __str__ content, potentially updated for new fields) ...
        final_chunk_info = []
        if self.gre_protocol: final_chunk_info.append(f"GRE_Proto:{self.gre_protocol}")
        if self.esp_spi: final_chunk_info.append(f"ESP_SPI:{self.esp_spi}")
        if self.quic_initial_packet_present is not None: final_chunk_info.append(f"QUIC_Initial:{self.quic_initial_packet_present}")
        if self.is_zscaler_ip is not None: final_chunk_info.append(f"ZscalerIP:{self.is_zscaler_ip}")
        if self.is_zpa_synthetic_ip is not None: final_chunk_info.append(f"ZPA_SynthIP:{self.is_zpa_synthetic_ip}")
        if self.ssl_inspection_active is not None: final_chunk_info.append(f"SSL_Inspect:{self.ssl_inspection_active}")
        if self.zscaler_policy_block_type: final_chunk_info.append(f"ZS_Block:{self.zscaler_policy_block_type}")
        final_chunk_str = ", ".join(final_chunk_info)

        return (
            f"Frame: {self.frame_number}, Time: {self.timestamp:.6f}, "
            f"IP: {self.source_ip or 'N/A'}:{self.source_port or 'N/A'} -> "
            f"{self.destination_ip or 'N/A'}:{self.destination_port or 'N/A'}, "
            f"L4_Proto: {self.protocol or 'N/A'}, "
            f"Extra: [{final_chunk_str if final_chunk_str else 'N/A'}], SNI: {self.sni if self.sni else 'N/A'}"
        )

def _safe_str_to_bool(value: Any) -> Optional[bool]:
    """Safely converts a string value (like '0', '1', 'true', 'false') to a boolean."""
    if isinstance(value, bool):
        return value
    s_val = str(value).lower().strip()
    if s_val == 'true' or s_val == '1':
        return True
    elif s_val == 'false' or s_val == '0':
        return False
    return None # Return None if conversion is not straightforward

def _get_pyshark_layer_attribute(layer: Any, attribute_name: str, frame_number_for_log: int, is_flag: bool = False) -> Any:
    """Helper to safely get an attribute from a pyshark layer."""
    if not hasattr(layer, attribute_name):
        return None
    
    raw_value = getattr(layer, attribute_name)
    
    if is_flag:
        bool_val = _safe_str_to_bool(raw_value)
        if bool_val is None and raw_value is not None: # Log if conversion failed but there was a value
             logger.warning(f"Frame {frame_number_for_log}: Could not convert flag '{attribute_name}' with value '{raw_value}' to bool. Using None.")
        return bool_val
        
    # For non-flag attributes that might need int conversion (e.g. port, ttl)
    # This part can be expanded or kept simple if direct string/int from pyshark is usually fine
    # For now, just returning raw_value for non-flags, assuming further type casting where needed
    return raw_value


def _extract_sni_pyshark(packet: pyshark.packet.packet.Packet) -> Optional[str]:
    logger.debug(f"Frame {packet.number}: Attempting SNI extraction (V_FIXED_ACCESS).")
    sni_value = None
    try:
        if not hasattr(packet, 'tls'): return None
        top_tls_layer = packet.tls
        if hasattr(top_tls_layer, '_all_fields'): logger.debug(f"Frame {packet.number}: Fields in top_tls_layer (packet.tls): {top_tls_layer._all_fields}")
        record_data = None;
        if hasattr(top_tls_layer, 'tls_record'): record_data = top_tls_layer.tls_record
        elif 'tls.record' in top_tls_layer.field_names: record_data = top_tls_layer.get_field_value('tls.record')
        else:
            if hasattr(top_tls_layer, 'tls_handshake'): record_data = top_tls_layer
        if not record_data:
            if hasattr(top_tls_layer, 'handshake_extensions_server_name'): sni_value = top_tls_layer.handshake_extensions_server_name
            return sni_value
        handshake_data = None
        if hasattr(record_data, 'tls_handshake'): handshake_data = record_data.tls_handshake
        elif 'tls.handshake' in record_data.field_names: handshake_data = record_data.get_field_value('tls.handshake')
        else: return sni_value
        if not handshake_data: return sni_value
        extension_data = None
        if hasattr(handshake_data, 'tls_handshake_extension'): extension_data = handshake_data.tls_handshake_extension
        elif 'tls.handshake.extension' in handshake_data.field_names: extension_data = handshake_data.get_field_value('tls.handshake.extension')
        else: return sni_value
        if not extension_data: return sni_value
        extensions_to_check = []
        if isinstance(extension_data, list): extensions_to_check.extend(extension_data)
        else: extensions_to_check.append(extension_data)
        for ext_entry in extensions_to_check:
            if hasattr(ext_entry, 'server_name_indication_extension'):
                sni_details_obj = ext_entry.server_name_indication_extension
                if hasattr(sni_details_obj, 'extensions_server_name'): sni_value = sni_details_obj.extensions_server_name; break
                elif hasattr(sni_details_obj, 'tls_handshake_extensions_server_name'): sni_value = sni_details_obj.tls_handshake_extensions_server_name; break
        if isinstance(sni_value, list): sni_value = sni_value[0] if sni_value else None
    except Exception as e: logger.error(f"Frame {packet.number}: General exception in _extract_sni_pyshark: {e}", exc_info=True); sni_value = None
    if sni_value is None: logger.debug(f"Frame {packet.number}: Final SNI extraction resulted in None.")
    else: logger.info(f"Frame {packet.number}: Final SNI value determined: {sni_value}")
    return sni_value

def _check_ip_in_ranges(ip_str: Optional[str], ranges: List[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    if not ip_str:
        return False
    try:
        ip_addr = ipaddress.ip_address(ip_str)
        for net_range in ranges:
            if ip_addr in net_range:
                return True
    except ValueError:
        logger.debug(f"Invalid IP address string for range check: {ip_str}")
        return False
    return False

def _parse_with_pyshark(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Starting PCAP parsing with PyShark for: {file_path}")
    generated_records = 0
    cap = None
    try:
        cap = pyshark.FileCapture(file_path, use_json=False, include_raw=False, keep_packets=False,
                                  custom_parameters=['-o', 'tls.desegment_ssl_records:TRUE',
                                                     '-o', 'tls.desegment_ssl_application_data:TRUE'])
    except pyshark.tshark.tshark.TSharkNotFoundException as e_tshark:
        logger.error(f"PyShark TSharkNotFoundException: {e_tshark}. Ensure TShark is installed and in PATH.")
        raise RuntimeError(f"PyShark critical error: TShark not found.") from e_tshark
    except Exception as e_init:
        logger.error(f"PyShark error opening/initializing pcap file {file_path}: {e_init}")
        raise RuntimeError(f"PyShark failed to open or initialize {file_path}.") from e_init

    packet_count = 0
    try:
        for packet in cap:
            if max_packets is not None and generated_records >= max_packets:
                logger.info(f"PyShark: Reached max_packets limit of {max_packets}.")
                break
            packet_count += 1
            try:
                timestamp = float(packet.sniff_timestamp)
                frame_number = int(packet.number)
               
                source_ip, destination_ip, source_port, destination_port, protocol_l4, sni = None, None, None, None, None, None
                source_mac, destination_mac, protocol_l3, packet_length_val = None, None, None, None
                ip_ttl, ip_flags_df_bool, ip_id_val, dscp_val = None, None, None, None # Renamed ip_flags_df to ip_flags_df_bool
                tcp_flags_syn, tcp_flags_ack, tcp_flags_fin, tcp_flags_rst = None, None, None, None
                tcp_flags_psh, tcp_flags_urg, tcp_flags_ece, tcp_flags_cwr = None, None, None, None
                tcp_sequence_number, tcp_acknowledgment_number, tcp_window_size = None, None, None
                tcp_options_mss, tcp_options_sack_permitted, tcp_options_window_scale = None, None, None
                tcp_stream_index = None
                tcp_analysis_retransmission, tcp_analysis_duplicate_ack = None, None
                tcp_analysis_out_of_order, tcp_analysis_zero_window = None, None
                tls_handshake_type_str, tls_handshake_version_str, tls_record_version_str = None, None, None
                tls_cipher_suites_offered_list, tls_cipher_suite_selected_str = None, None
                tls_alert_description_str, tls_alert_level_str = None, None
                dns_query_name_str, dns_query_type_str, dns_response_code_str = None, None, None
                dns_response_addresses_list, dns_response_cname_target_str = None, None
                http_request_method_str, http_request_uri_str, http_request_host_header_str = None, None, None
                http_response_code_int, http_response_location_header_str, http_x_forwarded_for_header_str = None, None, None
                icmp_type_val, icmp_code_val, icmp_frag_mtu_val = None, None, None
                arp_opcode_val, arp_sender_mac_str, arp_sender_ip_str = None, None, None
                arp_target_mac_str, arp_target_ip_str = None, None
                dhcp_message_type_str = None
                gre_protocol_str, esp_spi_str = None, None
                quic_initial_packet = None
                is_zscaler_ip_flag, is_zpa_synthetic_ip_flag = None, None # Will become False if IPs exist and don't match
                ssl_inspection_active_flag = None
                zscaler_policy_block_type_str = None
               
                raw_summary = str(packet.highest_layer) if hasattr(packet, 'highest_layer') else 'N/A'
                if hasattr(packet, 'length'): packet_length_val = int(packet.length)
                
                if hasattr(packet, 'eth'):
                    eth_layer = packet.eth
                    source_mac = _get_pyshark_layer_attribute(eth_layer, 'src', frame_number)
                    destination_mac = _get_pyshark_layer_attribute(eth_layer, 'dst', frame_number)

                ip_layer_obj = None
                if hasattr(packet, 'ip'):
                    protocol_l3 = "IPv4"; ip_layer_obj = packet.ip
                    proto_num_str = _get_pyshark_layer_attribute(ip_layer_obj, 'proto', frame_number)
                    if proto_num_str is not None:
                        protocol_num = int(proto_num_str)
                        if protocol_num == 1: protocol_l4 = "ICMP"
                        elif protocol_num == 6: protocol_l4 = "TCP"
                        elif protocol_num == 17: protocol_l4 = "UDP"
                        elif protocol_num == 47: protocol_l4 = "GRE"
                        elif protocol_num == 50: protocol_l4 = "ESP"
                        else: protocol_l4 = str(protocol_num)
                    source_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'src', frame_number)
                    destination_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'dst', frame_number)
                    ttl_str = _get_pyshark_layer_attribute(ip_layer_obj, 'ttl', frame_number)
                    if ttl_str: ip_ttl = int(ttl_str)
                    ip_flags_df_bool = _get_pyshark_layer_attribute(ip_layer_obj, 'flags_df', frame_number, is_flag=True)
                    ip_id_val = _get_pyshark_layer_attribute(ip_layer_obj, 'id', frame_number)
                    dscp_str = _get_pyshark_layer_attribute(ip_layer_obj, 'dsfield_dscp', frame_number)
                    if dscp_str: dscp_val = int(dscp_str)

                elif hasattr(packet, 'ipv6'):
                    protocol_l3 = "IPv6"; ip_layer_obj = packet.ipv6
                    proto_num_str = _get_pyshark_layer_attribute(ip_layer_obj, 'nxt', frame_number)
                    if proto_num_str is not None:
                        protocol_num = int(proto_num_str)
                        if protocol_num == 6: protocol_l4 = "TCP"
                        elif protocol_num == 17: protocol_l4 = "UDP"
                        elif protocol_num == 58: protocol_l4 = "ICMPv6"
                        elif protocol_num == 47: protocol_l4 = "GRE"
                        elif protocol_num == 50: protocol_l4 = "ESP"
                        else: protocol_l4 = str(protocol_num)
                    source_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'src', frame_number)
                    destination_ip = _get_pyshark_layer_attribute(ip_layer_obj, 'dst', frame_number)
                    hlim_str = _get_pyshark_layer_attribute(ip_layer_obj, 'hlim', frame_number)
                    if hlim_str: ip_ttl = int(hlim_str)
                    # IPv6 doesn't have a direct DF flag like IPv4. Fragmentation is handled by extension headers.
                    # DSCP from tclass
                    tclass_dscp_str = _get_pyshark_layer_attribute(ip_layer_obj, 'tclass_dscp', frame_number)
                    if tclass_dscp_str: 
                        dscp_val = int(tclass_dscp_str)
                    elif hasattr(ip_layer_obj, 'tclass'):
                        tclass_hex = _get_pyshark_layer_attribute(ip_layer_obj, 'tclass', frame_number)
                        if tclass_hex:
                            try: dscp_val = int(str(tclass_hex), 16) >> 2
                            except ValueError: logger.warning(f"Frame {frame_number}: Could not parse IPv6 tclass '{tclass_hex}' for DSCP.")
                
                elif hasattr(packet, 'arp'):
                    protocol_l3 = "ARP"
                    arp_layer = packet.arp
                    opcode_str = _get_pyshark_layer_attribute(arp_layer, 'opcode', frame_number)
                    if opcode_str: arp_opcode_val = int(opcode_str)
                    arp_sender_mac_str = _get_pyshark_layer_attribute(arp_layer, 'src_hw_mac', frame_number)
                    arp_sender_ip_str = _get_pyshark_layer_attribute(arp_layer, 'src_proto_ipv4', frame_number)
                    arp_target_mac_str = _get_pyshark_layer_attribute(arp_layer, 'dst_hw_mac', frame_number)
                    arp_target_ip_str = _get_pyshark_layer_attribute(arp_layer, 'dst_proto_ipv4', frame_number)
                else:
                    # For non-IP/non-ARP, yield basic L2 info if available
                    if packet_count > generated_records:
                         yield PcapRecord(
                            frame_number=frame_number, timestamp=timestamp,
                            source_mac=source_mac, destination_mac=destination_mac,
                            packet_length=packet_length_val, raw_packet_summary=raw_summary
                            # Other fields default to None
                         )
                         generated_records +=1
                    continue # Skip to next packet

                transport_layer_obj = None
                if protocol_l4 == "TCP" and hasattr(packet, 'tcp'):
                    transport_layer_obj = packet.tcp; tcp_layer = transport_layer_obj
                    tcp_flags_syn = _get_pyshark_layer_attribute(tcp_layer, 'flags_syn', frame_number, is_flag=True)
                    tcp_flags_ack = _get_pyshark_layer_attribute(tcp_layer, 'flags_ack', frame_number, is_flag=True)
                    tcp_flags_fin = _get_pyshark_layer_attribute(tcp_layer, 'flags_fin', frame_number, is_flag=True)
                    tcp_flags_rst = _get_pyshark_layer_attribute(tcp_layer, 'flags_rst', frame_number, is_flag=True)
                    tcp_flags_psh = _get_pyshark_layer_attribute(tcp_layer, 'flags_push', frame_number, is_flag=True) # pyshark uses 'flags_push'
                    tcp_flags_urg = _get_pyshark_layer_attribute(tcp_layer, 'flags_urg', frame_number, is_flag=True)
                    tcp_flags_ece = _get_pyshark_layer_attribute(tcp_layer, 'flags_ece', frame_number, is_flag=True)
                    tcp_flags_cwr = _get_pyshark_layer_attribute(tcp_layer, 'flags_cwr', frame_number, is_flag=True)
                    
                    seq_str = _get_pyshark_layer_attribute(tcp_layer, 'seq', frame_number)
                    if seq_str: tcp_sequence_number = int(seq_str)
                    ack_str = _get_pyshark_layer_attribute(tcp_layer, 'ack', frame_number)
                    if ack_str: tcp_acknowledgment_number = int(ack_str)
                    
                    win_val_str = _get_pyshark_layer_attribute(tcp_layer, 'window_size_value', frame_number)
                    if win_val_str: tcp_window_size = int(win_val_str)
                    else: # Fallback
                        win_str = _get_pyshark_layer_attribute(tcp_layer, 'window_size', frame_number)
                        if win_str: tcp_window_size = int(win_str)

                    stream_str = _get_pyshark_layer_attribute(tcp_layer, 'stream', frame_number)
                    if stream_str: tcp_stream_index = int(stream_str)

                    mss_val_str = _get_pyshark_layer_attribute(tcp_layer, 'options_mss_val', frame_number)
                    if mss_val_str: tcp_options_mss = int(mss_val_str)
                    else: # Fallback
                        mss_str = _get_pyshark_layer_attribute(tcp_layer, 'mss_val', frame_number)
                        if mss_str: tcp_options_mss = int(mss_str)
                    
                    sack_perm_str = _get_pyshark_layer_attribute(tcp_layer, 'options_sack_permit', frame_number) # Note: pyshark might use 'sack_perm' or 'options_sack_permit'
                    if sack_perm_str is not None: tcp_options_sack_permitted = _safe_str_to_bool(sack_perm_str)
                    else: # Fallback for older PyShark or different field name
                        sack_perm_alt_str = _get_pyshark_layer_attribute(tcp_layer, 'sack_perm', frame_number)
                        if sack_perm_alt_str is not None: tcp_options_sack_permitted = _safe_str_to_bool(sack_perm_alt_str)

                    wscale_val_str = _get_pyshark_layer_attribute(tcp_layer, 'options_wscale_val', frame_number)
                    if wscale_val_str: tcp_options_window_scale = int(wscale_val_str)
                    else: # Fallback for 'window_scale_multiplier' or 'ws_val'
                        wscale_mult_str = _get_pyshark_layer_attribute(tcp_layer, 'window_scale_multiplier', frame_number)
                        if wscale_mult_str: tcp_options_window_scale = int(wscale_mult_str)


                    if hasattr(tcp_layer, 'analysis'):
                        tcp_analysis_layer = tcp_layer.analysis
                        tcp_analysis_retransmission = hasattr(tcp_analysis_layer, 'retransmission')
                        tcp_analysis_duplicate_ack = hasattr(tcp_analysis_layer, 'duplicate_ack')
                        tcp_analysis_out_of_order = hasattr(tcp_analysis_layer, 'out_of_order')
                        tcp_analysis_zero_window = hasattr(tcp_analysis_layer, 'zero_window')

                elif protocol_l4 == "UDP" and hasattr(packet, 'udp'):
                    transport_layer_obj = packet.udp
                
                if transport_layer_obj:
                    srcport_str = _get_pyshark_layer_attribute(transport_layer_obj, 'srcport', frame_number)
                    if srcport_str: source_port = int(srcport_str)
                    dstport_str = _get_pyshark_layer_attribute(transport_layer_obj, 'dstport', frame_number)
                    if dstport_str: destination_port = int(dstport_str)

                if hasattr(packet, 'tls'):
                    sni = _extract_sni_pyshark(packet) # SNI extraction uses its own logic
                    tls_layer = packet.tls
                    raw_rec_ver = _get_pyshark_layer_attribute(tls_layer, 'version', frame_number)
                    if raw_rec_ver: tls_record_version_str = TLS_VERSION_MAP.get(str(raw_rec_ver).lower(), str(raw_rec_ver))

                    if hasattr(tls_layer, 'handshake'):
                        handshake_layer = tls_layer.handshake
                        hs_type_val = _get_pyshark_layer_attribute(handshake_layer, 'type', frame_number)
                        if hs_type_val: tls_handshake_type_str = TLS_HANDSHAKE_TYPE_MAP.get(str(hs_type_val), str(hs_type_val))
                        
                        hs_ver_val = _get_pyshark_layer_attribute(handshake_layer, 'version', frame_number)
                        if hs_ver_val: tls_handshake_version_str = TLS_VERSION_MAP.get(str(hs_ver_val).lower(), str(hs_ver_val))

                        if tls_handshake_type_str == "ClientHello" and hasattr(handshake_layer, 'ciphersuites'):
                            raw_suites = getattr(handshake_layer, 'ciphersuites') # Direct access for complex field
                            if isinstance(raw_suites, str): tls_cipher_suites_offered_list = [s.strip() for s in raw_suites.split(',')]
                            elif isinstance(raw_suites, list): tls_cipher_suites_offered_list = [str(s.show) for s in raw_suites] # .show for Field objects
                            else: tls_cipher_suites_offered_list = [str(raw_suites)]
                        
                        if tls_handshake_type_str == "ServerHello" and hasattr(handshake_layer, 'ciphersuite'):
                            # ciphersuite field might be a Field object, convert to string
                            raw_cs = getattr(handshake_layer, 'ciphersuite')
                            tls_cipher_suite_selected_str = str(raw_cs.show) if hasattr(raw_cs, 'show') else str(raw_cs)


                    if hasattr(tls_layer, 'record_content_type') and str(_get_pyshark_layer_attribute(tls_layer, 'record_content_type', frame_number)) == '21': # Alert
                        alert_level_val = _get_pyshark_layer_attribute(tls_layer, 'alert_message_level', frame_number)
                        if alert_level_val: tls_alert_level_str = TLS_ALERT_LEVEL_MAP.get(str(alert_level_val), str(alert_level_val))
                        
                        # Try 'alert_message_description' first as it's more direct from newer tshark
                        alert_desc_val = _get_pyshark_layer_attribute(tls_layer, 'alert_message_description', frame_number)
                        if alert_desc_val: tls_alert_description_str = TLS_ALERT_DESCRIPTION_MAP.get(str(alert_desc_val), str(alert_desc_val))
                        else: # Fallback to 'alert_message' if description not found
                            alert_msg_val = _get_pyshark_layer_attribute(tls_layer, 'alert_message', frame_number)
                            if alert_msg_val: tls_alert_description_str = TLS_ALERT_DESCRIPTION_MAP.get(str(alert_msg_val), str(alert_msg_val)) # Use same map
                            else: tls_alert_description_str = "Unknown Alert"


                if hasattr(packet, 'dns'):
                    dns_layer = packet.dns
                    dns_query_name_str = _get_pyshark_layer_attribute(dns_layer, 'qry_name', frame_number)
                    qry_type_val = _get_pyshark_layer_attribute(dns_layer, 'qry_type', frame_number)
                    if qry_type_val: dns_query_type_str = DNS_QUERY_TYPE_MAP.get(str(qry_type_val), str(qry_type_val))

                    if _get_pyshark_layer_attribute(dns_layer, 'flags_response', frame_number, is_flag=True): # Check if it's a response
                        rcode_val = _get_pyshark_layer_attribute(dns_layer, 'flags_rcode', frame_number)
                        if rcode_val: dns_response_code_str = DNS_RCODE_MAP.get(str(rcode_val), str(rcode_val))
                        
                        current_response_addrs = []
                        # Handling for 'a' and 'aaaa' which can be single or list of Field objects
                        for addr_type_attr in ['a', 'aaaa']:
                            if hasattr(dns_layer, addr_type_attr):
                                val_addr_field = getattr(dns_layer, addr_type_attr)
                                if isinstance(val_addr_field, list): # List of Field objects
                                    for item_addr in val_addr_field:
                                        current_response_addrs.append(str(item_addr.show) if hasattr(item_addr, 'show') else str(item_addr))
                                elif isinstance(val_addr_field, str): # Comma-separated string
                                     current_response_addrs.extend([addr.strip() for addr in val_addr_field.split(',') if addr.strip()])
                                else: # Single Field object or simple string
                                    current_response_addrs.append(str(val_addr_field.show) if hasattr(val_addr_field, 'show') else str(val_addr_field))
                        if current_response_addrs: dns_response_addresses_list = current_response_addrs
                        
                        if hasattr(dns_layer, 'cname'):
                            val_cname_field = getattr(dns_layer, 'cname')
                            if isinstance(val_cname_field, list) and val_cname_field: # Take the first if it's a list
                                dns_response_cname_target_str = str(val_cname_field[0].show) if hasattr(val_cname_field[0], 'show') else str(val_cname_field[0])
                            else: # Single Field object or simple string
                                dns_response_cname_target_str = str(val_cname_field.show) if hasattr(val_cname_field, 'show') else str(val_cname_field)


                if hasattr(packet, 'http'):
                    http_layer = packet.http
                    if hasattr(http_layer, 'request_method'):
                        http_request_method_str = _get_pyshark_layer_attribute(http_layer, 'request_method', frame_number)
                        http_request_uri_str = _get_pyshark_layer_attribute(http_layer, 'request_uri', frame_number)
                        http_request_host_header_str = _get_pyshark_layer_attribute(http_layer, 'host', frame_number)
                        http_x_forwarded_for_header_str = _get_pyshark_layer_attribute(http_layer, 'x_forwarded_for', frame_number)
                    elif hasattr(http_layer, 'response_code'):
                        resp_code_str = _get_pyshark_layer_attribute(http_layer, 'response_code', frame_number)
                        if resp_code_str: http_response_code_int = int(resp_code_str)
                        http_response_location_header_str = _get_pyshark_layer_attribute(http_layer, 'location', frame_number)
                    # If x_forwarded_for exists but not in request (e.g. response context, though less common)
                    elif hasattr(http_layer, 'x_forwarded_for') and not http_request_method_str:
                         http_x_forwarded_for_header_str = _get_pyshark_layer_attribute(http_layer, 'x_forwarded_for', frame_number)


                icmp_layer_to_process = None
                if protocol_l4 == "ICMP" and hasattr(packet, 'icmp'):
                    icmp_layer_to_process = packet.icmp
                elif protocol_l4 == "ICMPv6" and hasattr(packet, 'icmpv6'):
                    icmp_layer_to_process = packet.icmpv6

                if icmp_layer_to_process:
                    type_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'type', frame_number)
                    if type_str: icmp_type_val = int(type_str)
                    code_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'code', frame_number)
                    if code_str: icmp_code_val = int(code_str)

                    # ICMP Fragmentation Needed / Packet Too Big
                    is_frag_needed_v4 = (protocol_l4 == "ICMP" and icmp_type_val == 3 and icmp_code_val == 4)
                    is_packet_too_big_v6 = (protocol_l4 == "ICMPv6" and icmp_type_val == 2 and icmp_code_val == 0)

                    if is_frag_needed_v4 or is_packet_too_big_v6:
                        mtu_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'mtu', frame_number) # Common field name
                        if mtu_str: icmp_frag_mtu_val = int(mtu_str)
                        elif is_frag_needed_v4: # Fallback for ICMPv4 specific field name
                            nexthopmtu_str = _get_pyshark_layer_attribute(icmp_layer_to_process, 'nexthopmtu', frame_number)
                            if nexthopmtu_str: icmp_frag_mtu_val = int(nexthopmtu_str)

                # DHCP can be over 'bootp' layer in pyshark
                dhcp_layer_source = None
                if hasattr(packet, 'dhcp'):
                    dhcp_layer_source = packet.dhcp
                elif hasattr(packet, 'bootp') and hasattr(packet.bootp, 'option_dhcp_message_type'): # Check if bootp layer has DHCP options
                    dhcp_layer_source = packet.bootp
                
                if dhcp_layer_source:
                    msg_type_val = _get_pyshark_layer_attribute(dhcp_layer_source, 'option_dhcp_message_type', frame_number)
                    if msg_type_val: dhcp_message_type_str = DHCP_MESSAGE_TYPE_MAP.get(str(msg_type_val), str(msg_type_val))


                if protocol_l4 == "GRE" and hasattr(packet, 'gre'):
                    gre_layer = packet.gre
                    gre_protocol_str = _get_pyshark_layer_attribute(gre_layer, 'proto', frame_number)
               
                if protocol_l4 == "ESP" and hasattr(packet, 'esp'):
                    esp_layer = packet.esp
                    esp_spi_str = _get_pyshark_layer_attribute(esp_layer, 'spi', frame_number)

                if hasattr(packet, 'quic'):
                    quic_layer = packet.quic
                    if hasattr(quic_layer, 'version'):
                        # Check for long header type '0' (Initial)
                        long_packet_type = _get_pyshark_layer_attribute(quic_layer, 'long_packet_type', frame_number)
                        if str(long_packet_type) == '0':
                            quic_initial_packet = True
                        # Fallback: Check header_form '1' (Long header) if long_packet_type not definitive
                        elif _get_pyshark_layer_attribute(quic_layer, 'header_form', frame_number, is_flag=True): # '1' is Long Header
                            quic_initial_packet = True # Simplified, could be other long header types
                        else:
                            quic_initial_packet = False # It's QUIC, has version, but not clearly Initial or Long Header

                # Zscaler Contextual Variables
                # These are set regardless of whether IPs were found or not; _check_ip_in_ranges handles None IPs
                is_zscaler_ip_flag = _check_ip_in_ranges(source_ip, ZSCALER_EXAMPLE_IP_RANGES) or \
                                     _check_ip_in_ranges(destination_ip, ZSCALER_EXAMPLE_IP_RANGES)
                is_zpa_synthetic_ip_flag = _check_ip_in_ranges(source_ip, [ZPA_SYNTHETIC_IP_RANGE]) or \
                                           _check_ip_in_ranges(destination_ip, [ZPA_SYNTHETIC_IP_RANGE])
                
                # ssl_inspection_active: Still placeholder, requires cert parsing not yet implemented.
                # zscaler_policy_block_type
                if is_zscaler_ip_flag: # Only if one of the IPs is determined to be a Zscaler IP
                    is_zs_source = _check_ip_in_ranges(source_ip, ZSCALER_EXAMPLE_IP_RANGES)
                    if tcp_flags_rst and is_zs_source:
                        zscaler_policy_block_type_str = "TCP_RST_FROM_ZSCALER"
                    elif http_response_code_int and http_response_code_int >= 400 and is_zs_source:
                        if http_response_code_int == 403: zscaler_policy_block_type_str = "HTTP_403_FROM_ZSCALER"
                        elif http_response_code_int == 407: zscaler_policy_block_type_str = "HTTP_407_PROXY_AUTH_REQ_FROM_ZSCALER"
                        else: zscaler_policy_block_type_str = f"HTTP_{http_response_code_int}_FROM_ZSCALER"
                    elif tls_alert_level_str == "fatal" and tls_alert_description_str and is_zs_source:
                        safe_alert_desc = "".join(c if c.isalnum() or c in ['_'] else '_' for c in tls_alert_description_str)
                        zscaler_policy_block_type_str = f"TLS_FATAL_ALERT_FROM_ZSCALER_{safe_alert_desc[:30]}"


                yield PcapRecord(
                    frame_number=frame_number, timestamp=timestamp,
                    source_ip=source_ip, destination_ip=destination_ip,
                    source_port=source_port, destination_port=destination_port,
                    protocol=protocol_l4, sni=sni, raw_packet_summary=raw_summary,
                    source_mac=source_mac, destination_mac=destination_mac,
                    protocol_l3=protocol_l3, packet_length=packet_length_val,
                    ip_ttl=ip_ttl, ip_flags_df=ip_flags_df_bool, ip_id=ip_id_val, dscp_value=dscp_val,
                    tcp_flags_syn=tcp_flags_syn, tcp_flags_ack=tcp_flags_ack, 
                    tcp_flags_fin=tcp_flags_fin, tcp_flags_rst=tcp_flags_rst,
                    tcp_flags_psh=tcp_flags_psh, tcp_flags_urg=tcp_flags_urg,
                    tcp_flags_ece=tcp_flags_ece, tcp_flags_cwr=tcp_flags_cwr,
                    tcp_sequence_number=tcp_sequence_number, 
                    tcp_acknowledgment_number=tcp_acknowledgment_number,
                    tcp_window_size=tcp_window_size,
                    tcp_options_mss=tcp_options_mss,
                    tcp_options_sack_permitted=tcp_options_sack_permitted,
                    tcp_options_window_scale=tcp_options_window_scale,
                    tcp_stream_index=tcp_stream_index,
                    tcp_analysis_retransmission=tcp_analysis_retransmission,
                    tcp_analysis_duplicate_ack=tcp_analysis_duplicate_ack,
                    tcp_analysis_out_of_order=tcp_analysis_out_of_order,
                    tcp_analysis_zero_window=tcp_analysis_zero_window,
                    tls_handshake_type=tls_handshake_type_str,
                    tls_handshake_version=tls_handshake_version_str,
                    tls_record_version=tls_record_version_str,
                    tls_cipher_suites_offered=tls_cipher_suites_offered_list,
                    tls_cipher_suite_selected=tls_cipher_suite_selected_str,
                    tls_alert_message_description=tls_alert_description_str,
                    tls_alert_level=tls_alert_level_str,
                    dns_query_name=dns_query_name_str,
                    dns_query_type=dns_query_type_str,
                    dns_response_code=dns_response_code_str,
                    dns_response_addresses=dns_response_addresses_list,
                    dns_response_cname_target=dns_response_cname_target_str,
                    http_request_method=http_request_method_str,
                    http_request_uri=http_request_uri_str,
                    http_request_host_header=http_request_host_header_str,
                    http_response_code=http_response_code_int,
                    http_response_location_header=http_response_location_header_str,
                    http_x_forwarded_for_header=http_x_forwarded_for_header_str,
                    icmp_type=icmp_type_val,
                    icmp_code=icmp_code_val,
                    icmp_fragmentation_needed_original_mtu=icmp_frag_mtu_val,
                    arp_opcode=arp_opcode_val,
                    arp_sender_mac=arp_sender_mac_str,
                    arp_sender_ip=arp_sender_ip_str,
                    arp_target_mac=arp_target_mac_str,
                    arp_target_ip=arp_target_ip_str,
                    dhcp_message_type=dhcp_message_type_str,
                    gre_protocol=gre_protocol_str,
                    esp_spi=esp_spi_str,
                    quic_initial_packet_present=quic_initial_packet,
                    is_zscaler_ip=is_zscaler_ip_flag,
                    is_zpa_synthetic_ip=is_zpa_synthetic_ip_flag,
                    ssl_inspection_active=ssl_inspection_active_flag,
                    zscaler_policy_block_type=zscaler_policy_block_type_str
                )
                generated_records += 1
            except AttributeError as ae: # This should be less common with _get_pyshark_layer_attribute
                logger.warning(f"Frame {packet_count}: Attribute error processing packet details: {ae}. Packet Layers: {[l.layer_name for l in packet.layers if hasattr(l, 'layer_name')]}", exc_info=False) # exc_info=False to reduce noise if frequent
            except Exception as e_pkt: # Catch-all for other unexpected errors per packet
                logger.error(f"Frame {packet_count}: Error processing packet: {e_pkt}. Skipping.", exc_info=True) # Keep exc_info for unexpected
            
            if packet_count > 0 and packet_count % 1000 == 0 :
                logger.info(f"PyShark: Scanned {packet_count} packets...")
    except pyshark.capture.capture.TSharkCrashException as e_crash:
        logger.error(f"TShark crashed while processing {file_path}: {e_crash}")
        raise RuntimeError(f"TShark crashed, unable to process {file_path}.") from e_crash
    except Exception as e_cap_iter:
        logger.error(f"An error occurred during PyShark packet iteration in {file_path}: {e_cap_iter}", exc_info=True)
    finally:
        if cap: cap.close()
        logger.info(f"PyShark: Finished processing. Scanned {packet_count} packets, yielded {generated_records} records.")


def _parse_with_pcapkit(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Attempting to parse with PCAPKit (fallback): {file_path}")
    logger.warning("PCAPKit fallback: Most new fields are not implemented in this PcapKit path.")
    if False: yield # This makes it a generator
    logger.info("PCAPKit: Processing complete (stubbed).")
    return # Or raise StopIteration implicitly

def parse_pcap(file_path: str, max_packets: Optional[int] = None) -> pd.DataFrame:
    if not _USE_PYSHARK and not _USE_PCAPKIT:
        err_msg = "Neither PyShark nor PCAPKit is installed or available. Please install at least one."
        logger.critical(err_msg)
        raise RuntimeError(err_msg)
    
    records_list: List[PcapRecord] = []
    record_generator: Optional[Generator[PcapRecord, None, None]] = None
    parser_used = "None"

    if _USE_PYSHARK:
        logger.info("Attempting to parse with PyShark...")
        parser_used = "PyShark"
        try:
            record_generator = _parse_with_pyshark(file_path, max_packets)
        except RuntimeError as e_pyshark_init:
            logger.warning(f"PyShark primary parser failed: {e_pyshark_init}")
            if not _USE_PCAPKIT:
                logger.error("PyShark failed and PCAPKit fallback is not available. Cannot parse file.")
                raise
            logger.info("Falling back to PCAPKit...")
            record_generator = None 
            parser_used = "PCAPKit_Fallback_After_PyShark_Error"
        except Exception as e_pyshark_generic:
            logger.error(f"An unexpected error occurred with PyShark: {e_pyshark_generic}", exc_info=True)
            if not _USE_PCAPKIT:
                logger.error("PyShark failed and PCAPKit fallback is not available.")
                raise
            logger.info("Falling back to PCAPKit due to unexpected PyShark error...")
            record_generator = None
            parser_used = "PCAPKit_Fallback_After_PyShark_Error"
    
    if record_generator is None and _USE_PCAPKIT: # Fallback or if PyShark was not used
        if parser_used != "PCAPKit_Fallback_After_PyShark_Error": # Avoid double logging if PyShark failed
             logger.info("PyShark not used or available. Attempting to parse with PCAPKit...")
        parser_used = "PCAPKit"
        try:
            record_generator = _parse_with_pcapkit(file_path, max_packets)
        except FileNotFoundError:
            logger.error(f"PCAPKit error: File not found at {file_path}")
            raise
        except Exception as e_pcapkit:
            logger.error(f"PCAPKit failed to process the file: {e_pcapkit}", exc_info=True)
            # Avoid raising here if PyShark was the primary attempt and failed, let it be handled by lack of records
            # However, if PCAPKit was the only option, then raise
            if not _USE_PYSHARK: # Only raise if PCAPKit was the primary and only option
                 raise RuntimeError(f"PCAP parsing failed with {parser_used} for {file_path}.") from e_pcapkit

    if record_generator:
        logger.info(f"Collecting records using {parser_used}...")
        try:
            for record_idx, record in enumerate(record_generator):
                records_list.append(record)
                if max_packets is not None and len(records_list) >= max_packets:
                    break
        except Exception as e_gen:
            logger.error(f"Error consuming from record generator ({parser_used}): {e_gen}", exc_info=True)

        logger.info(f"Collected {len(records_list)} records using {parser_used}.")
    else:
        # This condition might be hit if PyShark was available but failed, and PCAPKit was also not available or failed silently.
        if not (_USE_PYSHARK and parser_used == "PyShark") and \
           not (_USE_PCAPKIT and parser_used.startswith("PCAPKit")): # Ensure some parser was supposed to run
             logger.error("No valid parser (PyShark or PCAPKit) was successfully initiated or yielded records.")
             # No raise here, let it return empty DF to be handled by caller, but log it as error.

    if not records_list:
        logger.warning(f"No records were parsed from '{file_path}' using {parser_used}. Returning an empty DataFrame.")
        # Ensure DataFrame has all columns even if empty
        all_field_names = [f.name for f in PcapRecord.__dataclass_fields__.values()]
        return pd.DataFrame(columns=all_field_names)

    df = pd.DataFrame([asdict(r) for r in records_list])
    logger.info(f"Successfully parsed {len(df)} records into a DataFrame using {parser_used}.")
    return df

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG, 
        format='%(asctime)s - %(name)s - %(levelname)s - [%(module)s.%(funcName)s:%(lineno)d] - %(message)s'
    )
    logger.info("Running PcapParser example from __main__ (with flag fixes)")
    try:
        current_script_path = Path(__file__).resolve()
        project_root = current_script_path.parent.parent.parent 
        test_pcap_file_path = project_root / "tests" / "fixtures" / "test_mixed_traffic.pcapng" 
        
        if not test_pcap_file_path.exists():
            # Try a local path if not found in standard fixtures (e.g., during dev)
            alt_path_str = "test_mixed_traffic.pcapng" # A common name for a test file
            logger.warning(f"Test PCAP '{test_pcap_file_path}' not found. Trying local '{alt_path_str}'.")
            test_pcap_file_path = Path(alt_path_str)
            if not test_pcap_file_path.exists():
                logger.error(f"Test PCAP file '{alt_path_str}' also not found. Please create it or update path.")
                logger.info(f"You can create one with: tshark -F pcapng -w {Path.cwd() / alt_path_str} -c 200")
                exit()
        
        test_pcap_file = str(test_pcap_file_path)
        logger.info(f"Attempting to parse '{test_pcap_file}' with max_packets=100...")
        df_packets = parse_pcap(test_pcap_file, max_packets=100)
        
        print(f"\n--- DataFrame (first {min(len(df_packets), 20)} rows) ---")
        print(f"Total rows in DataFrame: {len(df_packets)}")
        if not df_packets.empty:
            display_cols = [
                'frame_number', 'timestamp', 
                'source_ip', 'destination_ip', 'protocol','protocol_l3',
                'tcp_flags_syn', 'tcp_flags_rst', 'ip_flags_df', # To check flag parsing
                'gre_protocol', 'esp_spi', 'quic_initial_packet_present',
                'is_zscaler_ip', 'is_zpa_synthetic_ip', 
                'ssl_inspection_active', 'zscaler_policy_block_type',
                'raw_packet_summary'
            ]
            actual_cols = [col for col in display_cols if col in df_packets.columns]
            if not actual_cols: # if display_cols had names not in df_packets
                logger.warning("None of the selected display_cols are in the DataFrame. Printing all columns.")
                actual_cols = df_packets.columns.tolist()

            try:
                # For cleaner terminal output, convert bools to 0/1 or T/F strings if preferred for display
                # df_display = df_packets[actual_cols].copy()
                # for col in df_display.select_dtypes(include='bool').columns:
                #    df_display[col] = df_display[col].apply(lambda x: 'T' if x is True else ('F' if x is False else 'None'))
                print(df_packets[actual_cols].head(min(len(df_packets), 20)).to_markdown(index=False))
            except Exception as e_print:
                logger.error(f"Error printing DataFrame to markdown: {e_print}. Printing normally.")
                print(df_packets[actual_cols].head(min(len(df_packets), 20)))
        else:
            print("DataFrame is empty.")

    except NameError: # Should not happen with Path(__file__)
        logger.error("Could not determine path to test PCAP. Ensure __file__ is defined or provide an absolute path.")
    except Exception as e:
        logger.error(f"An error occurred in the example usage: {e}", exc_info=True)

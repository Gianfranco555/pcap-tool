"""Centralized constant definitions for pcap_tool."""

from __future__ import annotations

import ipaddress

# ---------------------------------------------------------------------------
# PCAP file magic numbers used for basic validation
# ---------------------------------------------------------------------------
MAGIC_PCAP_LE: bytes = b"\xd4\xc3\xb2\xa1"  # Little-endian PCAP
MAGIC_PCAP_BE: bytes = b"\xa1\xb2\xc3\xd4"  # Big-endian PCAP
MAGIC_PCAPNG: bytes = b"\x0a\x0d\x0d\x0a"  # PCAPNG format

# ---------------------------------------------------------------------------
# TLS helper dictionaries
# ---------------------------------------------------------------------------
TLS_HANDSHAKE_TYPE_MAP: dict[str, str] = {
    "0": "HelloRequest",
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "5": "EndOfEarlyData",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
    "24": "CertificateStatus",
    "25": "KeyUpdate",
}

TLS_VERSION_MAP: dict[str, str] = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

TLS_ALERT_LEVEL_MAP: dict[str, str] = {
    "1": "warning",
    "2": "fatal",
}

TLS_ALERT_DESCRIPTION_MAP: dict[str, str] = {
    "0": "close_notify",
    "10": "unexpected_message",
    "20": "bad_record_mac",
    "21": "decryption_failed_RESERVED",
    "22": "record_overflow",
    "30": "decompression_failure",
    "40": "handshake_failure",
    "41": "no_certificate_RESERVED",
    "42": "bad_certificate",
    "43": "unsupported_certificate",
    "44": "certificate_revoked",
    "45": "certificate_expired",
    "46": "certificate_unknown",
    "47": "illegal_parameter",
    "48": "unknown_ca",
    "49": "access_denied",
    "50": "decode_error",
    "51": "decrypt_error",
    "60": "export_restriction_RESERVED",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "86": "inappropriate_fallback",
    "90": "user_canceled",
    "100": "no_renegotiation_RESERVED",
    "110": "missing_extension",
    "111": "unsupported_extension",
    "112": "unrecognized_name",
    "113": "bad_certificate_status_response",
    "114": "unknown_psk_identity",
    "115": "certificate_required",
    "116": "no_application_protocol",
}

# ---------------------------------------------------------------------------
# DNS and DHCP helper dictionaries
# ---------------------------------------------------------------------------
DNS_QUERY_TYPE_MAP: dict[str, str] = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "43": "DS",
    "46": "RRSIG",
    "47": "NSEC",
    "48": "DNSKEY",
    "255": "ANY",
    "257": "CAA",
}

DNS_RCODE_MAP: dict[str, str] = {
    "0": "NOERROR",
    "1": "FORMERR",
    "2": "SERVFAIL",
    "3": "NXDOMAIN",
    "4": "NOTIMP",
    "5": "REFUSED",
}

DHCP_MESSAGE_TYPE_MAP: dict[str, str] = {
    "1": "Discover",
    "2": "Offer",
    "3": "Request",
    "4": "Decline",
    "5": "Ack",
    "6": "Nak",
    "7": "Release",
    "8": "Inform",
}

# ---------------------------------------------------------------------------
# Example IP ranges for Zscaler related heuristics
# ---------------------------------------------------------------------------
ZSCALER_EXAMPLE_IP_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("104.129.192.0/20"),
    ipaddress.ip_network("165.225.0.0/17"),
]

ZPA_SYNTHETIC_IP_RANGE: ipaddress.IPv4Network = ipaddress.ip_network("100.64.0.0/10")

__all__ = [
    "MAGIC_PCAP_LE",
    "MAGIC_PCAP_BE",
    "MAGIC_PCAPNG",
    "TLS_HANDSHAKE_TYPE_MAP",
    "TLS_VERSION_MAP",
    "TLS_ALERT_LEVEL_MAP",
    "TLS_ALERT_DESCRIPTION_MAP",
    "DNS_QUERY_TYPE_MAP",
    "DNS_RCODE_MAP",
    "DHCP_MESSAGE_TYPE_MAP",
    "ZSCALER_EXAMPLE_IP_RANGES",
    "ZPA_SYNTHETIC_IP_RANGE",
]

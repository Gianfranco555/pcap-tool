from __future__ import annotations

from typing import Any, Dict, Optional, TYPE_CHECKING

from ..models import PcapRecord
from ..parsers.utils import _safe_int
from . import PacketProcessor

if TYPE_CHECKING:  # pragma: no cover - type hints only
    from ..parsers.pyshark_parser import PacketExtractor

TLS_HANDSHAKE_TYPE_MAP: Dict[int, str] = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    5: "EndOfEarlyData",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
    24: "CertificateStatus",
    25: "KeyUpdate",
}

TLS_VERSION_MAP: Dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_ALERT_LEVEL_MAP: Dict[int, str] = {
    1: "warning",
    2: "fatal",
}

TLS_ALERT_DESCRIPTION_MAP: Dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed_RESERVED",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate_RESERVED",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction_RESERVED",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation_RESERVED",
    110: "missing_extension",
    111: "unsupported_extension",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "unknown_psk_identity",
    115: "certificate_required",
    116: "no_application_protocol",
}


def _extract_sni(packet: Any) -> Optional[str]:
    sni_value = None
    try:
        if not hasattr(packet, "tls"):
            return None
        top_tls_layer = packet.tls
        record_data = None
        if hasattr(top_tls_layer, "tls_record"):
            record_data = top_tls_layer.tls_record
        elif "tls.record" in getattr(top_tls_layer, "field_names", []):
            record_data = top_tls_layer.get_field_value("tls.record")
        else:
            if hasattr(top_tls_layer, "tls_handshake"):
                record_data = top_tls_layer
        if not record_data:
            if hasattr(top_tls_layer, "handshake_extensions_server_name"):
                sni_value = top_tls_layer.handshake_extensions_server_name
            return sni_value
        handshake_data = None
        if hasattr(record_data, "tls_handshake"):
            handshake_data = record_data.tls_handshake
        elif "tls.handshake" in getattr(record_data, "field_names", []):
            handshake_data = record_data.get_field_value("tls.handshake")
        else:
            return sni_value
        if not handshake_data:
            return sni_value
        extension_data = None
        if hasattr(handshake_data, "tls_handshake_extension"):
            extension_data = handshake_data.tls_handshake_extension
        elif "tls.handshake.extension" in getattr(handshake_data, "field_names", []):
            extension_data = handshake_data.get_field_value("tls.handshake.extension")
        else:
            return sni_value
        if not extension_data:
            return sni_value
        extensions_to_check = extension_data if isinstance(extension_data, list) else [extension_data]
        for ext_entry in extensions_to_check:
            if hasattr(ext_entry, "server_name_indication_extension"):
                sni_details_obj = ext_entry.server_name_indication_extension
                if hasattr(sni_details_obj, "extensions_server_name"):
                    sni_value = sni_details_obj.extensions_server_name
                    break
                elif hasattr(sni_details_obj, "tls_handshake_extensions_server_name"):
                    sni_value = sni_details_obj.tls_handshake_extensions_server_name
                    break
        if isinstance(sni_value, list):
            sni_value = sni_value[0] if sni_value else None
    except Exception:
        sni_value = None
    return sni_value


class TLSProcessor(PacketProcessor):
    """Extract TLS handshake and certificate details."""

    def reset(self) -> None:  # pragma: no cover - stateless
        return None

    def process_packet(self, extractor: "PacketExtractor", record: PcapRecord) -> Dict[str, Any]:
        if not hasattr(extractor.packet, "tls"):
            return {}
        result: Dict[str, Any] = {}
        result["sni"] = _extract_sni(extractor.packet)
        result["tls_record_version"] = TLS_VERSION_MAP.get(
            _safe_int(extractor.get("tls", "record_version", record.frame_number)),
            extractor.get("tls", "record_version", record.frame_number),
        )
        hs_type = extractor.get("tls", "handshake_type", record.frame_number)
        if hs_type is not None:
            result["tls_handshake_type"] = TLS_HANDSHAKE_TYPE_MAP.get(_safe_int(hs_type), str(hs_type))
        hs_ver = extractor.get("tls", "handshake_version", record.frame_number)
        if hs_ver is not None:
            result["tls_handshake_version"] = TLS_VERSION_MAP.get(_safe_int(hs_ver), str(hs_ver))
        result["tls_effective_version"] = result.get("tls_handshake_version") or result.get("tls_record_version")
        if extractor.get("tls", "record_content_type", record.frame_number) == "21":
            alert_level = extractor.get("tls", "alert_message_level", record.frame_number)
            alert_desc = extractor.get("tls", "alert_message_desc", record.frame_number)
            if alert_level is not None:
                result["tls_alert_level"] = TLS_ALERT_LEVEL_MAP.get(_safe_int(alert_level), str(alert_level))
            if alert_desc is not None:
                result["tls_alert_message_description"] = TLS_ALERT_DESCRIPTION_MAP.get(_safe_int(alert_desc), str(alert_desc))
        return {k: v for k, v in result.items() if v is not None}


__all__ = [
    "TLSProcessor",
    "TLS_HANDSHAKE_TYPE_MAP",
    "TLS_VERSION_MAP",
    "TLS_ALERT_LEVEL_MAP",
    "TLS_ALERT_DESCRIPTION_MAP",
]

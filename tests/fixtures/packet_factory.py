from __future__ import annotations

from scapy.all import load_layer
from scapy.packet import Packet
from scapy.fields import ByteEnumField, FieldLenField, StrLenField
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Raw

load_layer("tls")

# Dynamically determine ServerName classes similar to test_parser
ScapyServerNameClass = None
TLSExtensionServerNameClass = None
try:
    from scapy.layers.tls.extensions import ServerName as ModernScapyServerName
    from scapy.layers.tls.extensions import TLSExtensionServerName as ModernTLSExtensionServerName
    ScapyServerNameClass = ModernScapyServerName
    TLSExtensionServerNameClass = ModernTLSExtensionServerName
except ImportError:
    try:
        from scapy.layers.tls.extensions import TLS_Ext_ServerName as OlderTLSExtensionServerName
        TLSExtensionServerNameClass = OlderTLSExtensionServerName

        class FallbackScapyServerNameEntry(Packet):
            name = "ServerNameEntry (Fallback)"
            fields_desc = [
                ByteEnumField("name_type", 0, {0: "host_name"}),
                FieldLenField("name_len", None, length_of="servername", fmt="!H"),
                StrLenField("servername", b"", length_from=lambda pkt: pkt.name_len),
            ]

        ScapyServerNameClass = FallbackScapyServerNameEntry
    except Exception:
        ScapyServerNameClass = None
        TLSExtensionServerNameClass = None


class PacketFactory:
    """Utility factory for building common packets and flows."""

    @staticmethod
    def tcp_packet(
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        flags: str = "S",
        ttl: int = 64,
        src_mac: str | None = None,
        dst_mac: str | None = None,
        ip_flags: str = "DF",
    ) -> Packet:
        l2 = Ether(src=src_mac, dst=dst_mac) if src_mac or dst_mac else Ether()
        return l2 / IP(src=src_ip, dst=dst_ip, flags=ip_flags, ttl=ttl) / TCP(sport=sport, dport=dport, flags=flags)

    @staticmethod
    def udp_packet(
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        payload: bytes = b"",
        ttl: int = 64,
        src_mac: str | None = None,
        dst_mac: str | None = None,
        ip_flags: str = "DF",
    ) -> Packet:
        l2 = Ether(src=src_mac, dst=dst_mac) if src_mac or dst_mac else Ether()
        return (
            l2
            / IP(src=src_ip, dst=dst_ip, flags=ip_flags, ttl=ttl)
            / UDP(sport=sport, dport=dport)
            / Raw(load=payload)
        )

    @staticmethod
    def icmp_echo_request(
        src_ip: str,
        dst_ip: str,
        ttl: int = 64,
        src_mac: str | None = None,
        dst_mac: str | None = None,
        ip_flags: str = "DF",
    ) -> Packet:
        return PacketFactory.icmp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            ttl=ttl,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ip_flags=ip_flags,
            icmp_type="echo-request",
        )

    @staticmethod
    def icmp_packet(
        src_ip: str,
        dst_ip: str,
        icmp_type: int | str = 8,
        code: int = 0,
        ttl: int = 64,
        src_mac: str | None = None,
        dst_mac: str | None = None,
        ip_flags: str = "DF",
        **kwargs,
    ) -> Packet:
        l2 = Ether(src=src_mac, dst=dst_mac) if src_mac or dst_mac else Ether()
        return (
            l2
            / IP(src=src_ip, dst=dst_ip, flags=ip_flags, ttl=ttl)
            / ICMP(type=icmp_type, code=code, **kwargs)
        )

    @staticmethod
    def dns_query(
        src_ip: str,
        dst_ip: str = "8.8.8.8",
        sport: int = 12345,
        qname: str = "example.com",
    ) -> Packet:
        return Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname=qname))

    @staticmethod
    def dns_response(
        src_ip: str = "8.8.8.8",
        dst_ip: str = "1.1.1.1",
        dport: int = 12345,
        qname: str = "example.com",
        rdata: str = "93.184.216.34",
    ) -> Packet:
        return (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=53, dport=dport)
            / DNS(id=1, qr=1, aa=1, rcode=0, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata=rdata))
        )

    @staticmethod
    def arp_request(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> Packet:
        return Ether(src=src_mac, dst=dst_mac) / ARP(pdst=dst_ip, psrc=src_ip, hwsrc=src_mac, hwdst=dst_mac, op=1)

    @staticmethod
    def tls_client_hello(
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int = 443,
        sni: str = "example.com",
        src_mac: str | None = None,
        dst_mac: str | None = None,
    ) -> Packet:
        if ScapyServerNameClass is None or TLSExtensionServerNameClass is None:
            raise ImportError("TLS classes not available for building ClientHello")
        server_name_entry_obj = ScapyServerNameClass(servername=sni.encode())
        sni_extension_obj = TLSExtensionServerNameClass(servernames=[server_name_entry_obj])
        client_hello_obj = TLSClientHello(version=0x0303, ext=[sni_extension_obj])
        client_hello_bytes = bytes(client_hello_obj)
        tls_record_obj = TLS(type=22, version=0x0303, len=len(client_hello_bytes)) / Raw(load=client_hello_bytes)
        l2 = Ether(src=src_mac, dst=dst_mac) if src_mac or dst_mac else Ether()
        return l2 / IP(src=src_ip, dst=dst_ip, flags="DF") / TCP(sport=sport, dport=dport, flags="PA") / tls_record_obj

    # ----- Flow builders -----
    @classmethod
    def tcp_handshake_flow(
        cls,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        src_mac: str | None = None,
        dst_mac: str | None = None,
    ) -> list[Packet]:
        syn = cls.tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=sport,
            dport=dport,
            flags="S",
            src_mac=src_mac,
            dst_mac=dst_mac,
        )
        synack = cls.tcp_packet(
            src_ip=dst_ip,
            dst_ip=src_ip,
            sport=dport,
            dport=sport,
            flags="SA",
            src_mac=dst_mac,
            dst_mac=src_mac,
        )
        ack = cls.tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=sport,
            dport=dport,
            flags="A",
            src_mac=src_mac,
            dst_mac=dst_mac,
        )
        return [syn, synack, ack]

    @classmethod
    def dns_query_response_flow(cls, src_ip: str, dst_ip: str = "8.8.8.8", qname: str = "example.com") -> list[Packet]:
        query = cls.dns_query(src_ip, dst_ip, 12345, qname)
        response = cls.dns_response(dst_ip, src_ip, 12345, qname)
        return [query, response]

    # ----- Error scenario builders -----
    @classmethod
    def malformed_tls_flow(cls, src_ip: str, dst_ip: str) -> list[Packet]:
        pkt1 = cls.tcp_packet(src_ip, dst_ip, 23456, 443, "S")
        pkt2 = (
            cls.tcp_packet(src_ip, dst_ip, 23456, 443, "PA")
            / Raw(load=b"This is not a TLS packet payload.")
        )
        ch_no_sni = TLSClientHello(ext=None)
        tls_no_sni = TLS(type=22, version=0x0303) / ch_no_sni
        pkt3 = cls.tcp_packet(src_ip, dst_ip, 23457, 443, "PA") / tls_no_sni
        return [pkt1, pkt2, pkt3]

    @staticmethod
    def non_ip_packet(src_mac: str, dst_mac: str, eth_type: int = 0x88B5) -> Packet:
        return Ether(dst=dst_mac, src=src_mac, type=eth_type)


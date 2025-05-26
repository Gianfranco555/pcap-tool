from __future__ import annotations

from pathlib import Path
from typing import Iterable

from scapy.utils import PcapWriter

from .packet_factory import PacketFactory


class PcapBuilder:
    """Helper for programmatically creating pcap files for tests."""

    @staticmethod
    def build(packets: Iterable, output_path: Path) -> Path:
        with PcapWriter(str(output_path), sync=True) as writer:
            for pkt in packets:
                writer.write(pkt)
        return output_path

    @classmethod
    def build_in_temp(cls, packets: Iterable, tmp_path: Path, filename: str) -> Path:
        return cls.build(packets, tmp_path / filename)

    # Convenience scenario builders
    @classmethod
    def handshake_pcap(cls, tmp_path: Path, **kwargs) -> Path:
        pkts = PacketFactory.tcp_handshake_flow(**kwargs)
        return cls.build_in_temp(pkts, tmp_path, "handshake.pcap")

    @classmethod
    def dns_query_response_pcap(cls, tmp_path: Path, **kwargs) -> Path:
        pkts = PacketFactory.dns_query_response_flow(**kwargs)
        return cls.build_in_temp(pkts, tmp_path, "dns_qr.pcap")


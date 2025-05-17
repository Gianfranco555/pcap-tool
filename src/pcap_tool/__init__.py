# src/pcap_tool/__init__.py
from .parser import parse_pcap, PcapRecord   # ← re-export the function & dataclass
__all__ = ["parse_pcap", "PcapRecord"]


# src/pcap_parser/parser.py
from dataclasses import dataclass, asdict, field
from typing import Optional, Iterator, Any, Generator, List
import logging
import pandas as pd # Added pandas import

# Configure basic logging
logger = logging.getLogger(__name__)

# --- Library Import and Selection ---
_USE_PYSHARK = False
_USE_PCAPKIT = False

try:
    import pyshark
    _USE_PYSHARK = True
    logger.info("PyShark library found and will be used as the primary parser.")
except ImportError:
    logger.warning("PyShark library not found.")

try:
    from pcapkit import extract as pcapkit_extract
    from pcapkit.protocols.link import ethernet as pcapkit_ethernet
    from pcapkit.protocols.internet import ip as pcapkit_ip
    from pcapkit.protocols.internet import ipv6 as pcapkit_ipv6
    from pcapkit.protocols.transport import tcp as pcapkit_tcp
    from pcapkit.protocols.transport import udp as pcapkit_udp
    _USE_PCAPKIT = True
    if not _USE_PYSHARK:
        logger.info("PCAPKit library found and will be used as a fallback parser.")
except ImportError:
    logger.warning("PCAPKit library not found. At least one parser (PyShark or PCAPKit) is required.")

if not _USE_PYSHARK and not _USE_PCAPKIT:
    logger.error("Neither PyShark nor PCAPKit is available. PCAP parsing will not function.")

# --- PcapRecord Dataclass ---
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

    def __str__(self):
        return (
            f"Frame: {self.frame_number}, Time: {self.timestamp:.6f}, "
            f"{self.source_ip or 'N/A'}:{self.source_port or 'N/A'} -> "
            f"{self.destination_ip or 'N/A'}:{self.destination_port or 'N/A'}, "
            f"Proto: {self.protocol or 'N/A'}, SNI: {self.sni if self.sni else 'N/A'}"
        )

# --- PyShark Parsing Logic ---
def _extract_sni_pyshark(packet: pyshark.packet.packet.Packet) -> Optional[str]:
    try:
        if "TLS" in packet and hasattr(packet.tls, 'handshake_extensions_server_name'):
            return packet.tls.handshake_extensions_server_name
        if hasattr(packet, 'ssl') and hasattr(packet.ssl, 'handshake_extensions_server_name'):
            return packet.ssl.handshake_extensions_server_name
    except AttributeError:
        pass
    return None

def _parse_with_pyshark(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Starting PCAP parsing with PyShark for: {file_path}")
    generated_records = 0
    try:
        cap = pyshark.FileCapture(file_path, use_json=True, include_raw=True, keep_packets=False)
    except Exception as e:
        logger.error(f"PyShark error opening pcap file {file_path}: {e}")
        raise RuntimeError(f"PyShark failed to open {file_path}. Ensure TShark is installed and in PATH.") from e

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
                source_ip, destination_ip, source_port, destination_port, protocol, sni = None, None, None, None, None, None
                raw_summary = str(packet.highest_layer) if hasattr(packet, 'highest_layer') else 'N/A'

                if 'IP' in packet:
                    ip_layer = packet.ip
                    source_ip = ip_layer.src
                    destination_ip = ip_layer.dst
                    protocol_num = int(ip_layer.proto)
                    if protocol_num == 1: protocol = "ICMP"
                    elif protocol_num == 6: protocol = "TCP"
                    elif protocol_num == 17: protocol = "UDP"
                    else: protocol = str(protocol_num)
                elif 'IPV6' in packet:
                    ipv6_layer = packet.ipv6
                    source_ip = ipv6_layer.src
                    destination_ip = ipv6_layer.dst
                    protocol_num = int(ipv6_layer.nxt)
                    if protocol_num == 6: protocol = "TCP"
                    elif protocol_num == 17: protocol = "UDP"
                    elif protocol_num == 58: protocol = "ICMPv6"
                    else: protocol = str(protocol_num)
                else:
                    desc = ', '.join([str(layer.layer_name) for layer in packet.layers])
                    yield PcapRecord(frame_number=frame_number, timestamp=timestamp, raw_packet_summary=f"L2: {desc}")
                    generated_records += 1
                    continue

                if protocol == "TCP" and 'TCP' in packet:
                    tcp_layer = packet.tcp
                    source_port = int(tcp_layer.srcport)
                    destination_port = int(tcp_layer.dstport)
                    sni = _extract_sni_pyshark(packet)
                elif protocol == "UDP" and 'UDP' in packet:
                    udp_layer = packet.udp
                    source_port = int(udp_layer.srcport)
                    destination_port = int(udp_layer.dstport)
                    if 'DTLS' in packet or hasattr(packet, 'ssl'):
                         sni = _extract_sni_pyshark(packet)

                yield PcapRecord(
                    frame_number=frame_number, timestamp=timestamp,
                    source_ip=source_ip, destination_ip=destination_ip,
                    source_port=source_port, destination_port=destination_port,
                    protocol=protocol, sni=sni, raw_packet_summary=raw_summary
                )
                generated_records += 1

            except AttributeError as ae:
                logger.warning(f"Frame {packet_count}: Attribute error processing packet: {ae}. Packet layers: {packet.layers}")
            except Exception as e_pkt:
                logger.error(f"Frame {packet_count}: Error processing packet: {e_pkt}. Skipping.")
            
            if packet_count % 1000 == 0:
                logger.info(f"PyShark: Scanned {packet_count} packets...")

    except pyshark.capture.capture.TSharkCrashException as e:
        logger.error(f"TShark crashed while processing {file_path}: {e}")
    except Exception as e_cap:
        logger.error(f"An error occurred during PyShark packet iteration in {file_path}: {e_cap}")
    finally:
        if 'cap' in locals() and cap:
             cap.close()
        logger.info(f"PyShark: Finished processing. Scanned packets: {packet_count}, Yielded records: {generated_records}")

# --- PCAPKit Parsing Logic ---
def _parse_with_pcapkit(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Starting PCAP parsing with PCAPKit for: {file_path}")
    logger.warning("PCAPKit fallback: SNI parsing is currently not supported in this mode.")
    generated_records = 0
    packet_count = 0
    try:
        extraction = pcapkit_extract(fin=file_path, store=False, auto_eof=True)

        for frame_data in extraction:
            if max_packets is not None and generated_records >= max_packets:
                logger.info(f"PCAPKit: Reached max_packets limit of {max_packets}.")
                break
            packet_count += 1
            try:
                frame_number = frame_data.number if hasattr(frame_data, 'number') else packet_count
                timestamp = frame_data.timestamp
                source_ip, destination_ip, source_port, destination_port, protocol, sni = None, None, None, None, None, None
                raw_summary = "N/A"

                if pcapkit_ethernet.Ethernet in frame_data:
                    eth_frame = frame_data[pcapkit_ethernet.Ethernet]
                    if eth_frame.type == pcapkit_ethernet.EtherType.IPv4 and pcapkit_ip.IP in frame_data:
                        ip_pkt = frame_data[pcapkit_ip.IP]
                        source_ip = str(ip_pkt.src)
                        destination_ip = str(ip_pkt.dst)
                        protocol_num = ip_pkt.protocol.value
                        raw_summary = f"IPv4/{ip_pkt.protocol.name}"
                        if protocol_num == 1: protocol = "ICMP"
                        elif protocol_num == 6: protocol = "TCP"
                        elif protocol_num == 17: protocol = "UDP"
                        else: protocol = str(ip_pkt.protocol.name)
                        if protocol == "TCP" and pcapkit_tcp.TCP in frame_data:
                            tcp_pkt = frame_data[pcapkit_tcp.TCP]
                            source_port = tcp_pkt.srcport
                            destination_port = tcp_pkt.dstport
                        elif protocol == "UDP" and pcapkit_udp.UDP in frame_data:
                            udp_pkt = frame_data[pcapkit_udp.UDP]
                            source_port = udp_pkt.srcport
                            destination_port = udp_pkt.dstport
                    elif eth_frame.type == pcapkit_ethernet.EtherType.IPv6 and pcapkit_ipv6.IPv6 in frame_data:
                        ipv6_pkt = frame_data[pcapkit_ipv6.IPv6]
                        source_ip = str(ipv6_pkt.src)
                        destination_ip = str(ipv6_pkt.dst)
                        protocol_num = ipv6_pkt.next_header.value
                        raw_summary = f"IPv6/{ipv6_pkt.next_header.name}"
                        if protocol_num == 6: protocol = "TCP"
                        elif protocol_num == 17: protocol = "UDP"
                        elif protocol_num == 58: protocol = "ICMPv6"
                        else: protocol = str(ipv6_pkt.next_header.name)
                        if protocol == "TCP" and pcapkit_tcp.TCP in frame_data:
                            tcp_pkt = frame_data[pcapkit_tcp.TCP]
                            source_port = tcp_pkt.srcport
                            destination_port = tcp_pkt.dstport
                        elif protocol == "UDP" and pcapkit_udp.UDP in frame_data:
                            udp_pkt = frame_data[pcapkit_udp.UDP]
                            source_port = udp_pkt.srcport
                            destination_port = udp_pkt.dstport
                    else:
                        raw_summary = f"L2: {eth_frame.name}"
                        yield PcapRecord(frame_number=frame_number, timestamp=timestamp, raw_packet_summary=raw_summary)
                        generated_records += 1
                        continue
                else:
                    raw_summary = "Non-Ethernet or unknown L2"
                    yield PcapRecord(frame_number=frame_number, timestamp=timestamp, raw_packet_summary=raw_summary)
                    generated_records +=1
                    continue

                yield PcapRecord(
                    frame_number=frame_number, timestamp=timestamp,
                    source_ip=source_ip, destination_ip=destination_ip,
                    source_port=source_port, destination_port=destination_port,
                    protocol=protocol, sni=sni, raw_packet_summary=raw_summary
                )
                generated_records += 1
            except Exception as e_pkt:
                logger.error(f"PCAPKit: Frame {packet_count}: Error processing packet: {e_pkt}. Skipping.")
            if packet_count % 1000 == 0:
                logger.info(f"PCAPKit: Scanned {packet_count} packets...")
    except FileNotFoundError:
        logger.error(f"PCAPKit error: File not found at {file_path}")
        raise
    except Exception as e_cap:
        logger.error(f"An error occurred during PCAPKit processing of {file_path}: {e_cap}")
    finally:
        logger.info(f"PCAPKit: Finished processing. Scanned packets: {packet_count}, Yielded records: {generated_records}")

# --- Main Dispatcher ---
def parse_pcap(file_path: str, max_packets: Optional[int] = None) -> pd.DataFrame:
    """
    Parses a PCAP/PCAP-NG file and returns a pandas DataFrame of PcapRecord objects.
    Tries PyShark first, falls back to PCAPKit if PyShark is unavailable
    or fails to initialize. Limits records by max_packets if provided.

    Args:
        file_path: Path to the PCAP or PCAP-NG file.
        max_packets: Optional maximum number of PcapRecord objects to return.

    Returns:
        A pandas DataFrame containing the parsed packet data.

    Raises:
        RuntimeError: If neither PyShark nor PCAPKit is installed and usable,
                      or if the file cannot be processed by either.
        FileNotFoundError: If the pcap file does not exist.
    """
    if not _USE_PYSHARK and not _USE_PCAPKIT:
        err_msg = "Neither PyShark nor PCAPKit is installed or available. Please install at least one."
        logger.critical(err_msg)
        raise RuntimeError(err_msg)

    records_list: List[PcapRecord] = []
    record_generator: Optional[Generator[PcapRecord, None, None]] = None

    if _USE_PYSHARK:
        logger.info("Attempting to parse with PyShark...")
        try:
            record_generator = _parse_with_pyshark(file_path, max_packets)
        except RuntimeError as e_pyshark_init:
            logger.warning(f"PyShark initialization failed: {e_pyshark_init}")
            if not _USE_PCAPKIT:
                logger.error("PyShark failed and PCAPKit is not available. Cannot parse file.")
                raise
            logger.info("Falling back to PCAPKit...")
            record_generator = None # Ensure it's reset
        except Exception as e_pyshark:
            logger.warning(f"An unexpected error occurred with PyShark: {e_pyshark}")
            if not _USE_PCAPKIT:
                logger.error("PyShark failed and PCAPKit is not available. Cannot parse file.")
                raise
            logger.info("Falling back to PCAPKit...")
            record_generator = None # Ensure it's reset

    if record_generator is None and _USE_PCAPKIT: # Fallback or PyShark was not attempted
        logger.info("Attempting to parse with PCAPKit...")
        try:
            record_generator = _parse_with_pcapkit(file_path, max_packets)
        except Exception as e_pcapkit:
            logger.error(f"PCAPKit also failed to process the file: {e_pcapkit}")
            raise RuntimeError(f"Both PyShark and PCAPKit failed to parse {file_path}.") from e_pcapkit
    
    if record_generator:
        for record in record_generator:
            records_list.append(record)
            # The max_packets limit is now primarily enforced within the generator functions (_parse_with_pyshark/_parse_with_pcapkit)
            # This secondary check is a safeguard if somehow the generator produced more.
            if max_packets is not None and len(records_list) >= max_packets:
                logger.info(f"Main dispatcher: Reached max_packets limit of {max_packets} during collection.")
                break
    else:
        # This should only be reached if PyShark was not available AND PCAPKit was not available,
        # which is caught at the beginning, or if both failed sequentially.
        if not _USE_PYSHARK and not _USE_PCAPKIT: # Should have been caught
             raise RuntimeError("Neither PyShark nor PCAPKit is available. Cannot parse file.")
        # If we reach here, it means the chosen parser failed to even start yielding (e.g. file not found by it)
        # and the error wasn't propagated in a way that stopped execution, or no records were yielded.
        # The specific error should have been raised by the _parse_with_ methods or the fallback logic.

    # Convert list of dataclass objects to DataFrame
    if not records_list:
        logger.warning(f"No records were parsed from '{file_path}'. Returning an empty DataFrame.")
        return pd.DataFrame([asdict(PcapRecord(frame_number=0, timestamp=0.0))]).iloc[0:0] # Schema from empty PcapRecord

    # Convert list of PcapRecord objects to DataFrame
    # Using asdict helps in converting dataclasses to a dict list first
    df = pd.DataFrame([asdict(r) for r in records_list])
    logger.info(f"Successfully parsed {len(df)} records into a DataFrame.")
    return df

if __name__ == '__main__':
    # --- Example Usage ---
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("Running PcapParser example from __main__")

    # Create a dummy pcap for testing if you don't have one.
    # Ensure Wireshark/TShark is installed for this to work.
    # Example: tshark -F pcapng -w test_capture.pcapng -c 20 -i <your_interface_name_or_number>
    pcap_file = "test_capture.pcapng"

    import os
    if not os.path.exists(pcap_file):
        logger.error(f"Test PCAP file '{pcap_file}' not found in the current directory ({os.getcwd()}).")
        logger.info(f"Please create a test PCAP file (e.g., using `tshark -F pcapng -w {pcap_file} -c 20`)")
        logger.info(f"Or, update the `pcap_file` variable in the __main__ block.")
    else:
        logger.info(f"Attempting to parse '{pcap_file}' with max_packets=10...")
        try:
            # Note: For the smoke test format `from pcap_tool.parser import parse_pcap`,
            # your project structure and PYTHONPATH need to align.
            # This __main__ block directly calls parse_pcap as defined in this file.
            df_packets = parse_pcap(pcap_file, max_packets=10)
            print(f"\n--- DataFrame (first {min(len(df_packets), 10)} rows) ---")
            print(f"Total rows in DataFrame: {len(df_packets)}")
            if not df_packets.empty:
                # For older pandas versions, df.to_markdown() might not be available or might need `pip install tabulate`
                try:
                    print(df_packets.head(min(len(df_packets), 10)).to_markdown(index=False))
                except Exception as md_err:
                    print(f"(Could not print as markdown: {md_err})")
                    print(df_packets.head(min(len(df_packets), 10)))
            else:
                print("DataFrame is empty.")

            logger.info("\n--- Example: Parsing without max_packets (will process all) ---")
            # df_all_packets = parse_pcap(pcap_file)
            # logger.info(f"Total rows in DataFrame (all packets): {len(df_all_packets)}")
            # print(df_all_packets.head(3).to_markdown(index=False))

        except FileNotFoundError:
            logger.error(f"Error: The PCAP file '{pcap_file}' was not found during parsing.")
        except RuntimeError as e:
            logger.error(f"Runtime error during parsing: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred in the example usage: {e}", exc_info=True)
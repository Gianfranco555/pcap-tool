# src/pcap_tool/parser.py
from dataclasses import dataclass, asdict # Removed 'field' as it's not used
from typing import Optional, Generator, List # Removed Iterator, Any as they aren't used directly in type hints here
import logging
import pandas as pd

# Configure basic logging (ensure this is configured for your application, e.g., in __main__ or main app entry point)
logger = logging.getLogger(__name__)

# --- Library Import and Selection ---
_USE_PYSHARK = False
_USE_PCAPKIT = False

try:
    import pyshark
    _USE_PYSHARK = True
    logger.info("PyShark library found and will be used as the primary parser.")
except ImportError:
    logger.warning("PyShark library not found. Attempting PCAPKit.")

if not _USE_PYSHARK: # Try PCAPKit only if PyShark is not available
    try:
        from pcapkit import extract as pcapkit_extract
        from pcapkit.protocols.link import ethernet as pcapkit_ethernet
        from pcapkit.protocols.internet import ip as pcapkit_ip
        from pcapkit.protocols.internet import ipv6 as pcapkit_ipv6
        from pcapkit.protocols.transport import tcp as pcapkit_tcp
        from pcapkit.protocols.transport import udp as pcapkit_udp
        _USE_PCAPKIT = True
        logger.info("PCAPKit library found and will be used as a fallback parser.")
    except ImportError:
        logger.warning("PCAPKit library not found.")

if not _USE_PYSHARK and not _USE_PCAPKIT:
    # This error will be raised by parse_pcap if both are missing
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

# --- PyShark Parsing Logic ---.

# src/pcap_tool/parser.py

# src/pcap_tool/parser.py
# Ensure other imports and logger are defined correctly at the top of the file.

# src/pcap_tool/parser.py

def _extract_sni_pyshark(packet: pyshark.packet.packet.Packet) -> Optional[str]:
    logger.debug(f"Frame {packet.number}: Attempting SNI extraction (V_FIXED_ACCESS).")
    sni_value = None
    try:
        if not hasattr(packet, 'tls'):
            logger.debug(f"Frame {packet.number}: Packet has no 'tls' layer.")
            return None

        top_tls_layer = packet.tls # This is the PyShark Layer object for 'tls'
        logger.debug(f"Frame {packet.number}: Found 'tls' layer attribute (top_tls_layer).")

        # Log its fields for confirmation ONE LAST TIME - this is our map
        if hasattr(top_tls_layer, '_all_fields'):
            logger.debug(f"Frame {packet.number}: Fields in top_tls_layer (packet.tls): {top_tls_layer._all_fields}")
        
        record_data = None
        # The _all_fields shows 'tls.record' is a field within the top_tls_layer.
        # PyShark usually makes 'foo.bar' accessible as attribute 'foo_bar'.
        if hasattr(top_tls_layer, 'tls_record'): 
            record_data = top_tls_layer.tls_record
            logger.debug(f"Frame {packet.number}: Accessed 'tls_record' attribute from top_tls_layer.")
        elif 'tls.record' in top_tls_layer.field_names: # Fallback to get_field_value if attribute not found
            record_data = top_tls_layer.get_field_value('tls.record')
            logger.debug(f"Frame {packet.number}: Accessed 'tls.record' field via get_field_value from top_tls_layer.")
        else:
            logger.debug(f"Frame {packet.number}: Could not find 'tls_record' attribute or 'tls.record' field in top_tls_layer.")
            # If no 'tls.record', perhaps top_tls_layer IS the record data. Check for handshake directly.
            # This path would be taken if PyShark simplifies for very direct TLS structures.
            # For your logged structure, this path should NOT be taken if 'tls_record' is found above.
            if hasattr(top_tls_layer, 'tls_handshake'):
                 record_data = top_tls_layer # Treat top_tls_layer as the record_data
                 logger.debug(f"Frame {packet.number}: No 'tls_record' found, assuming top_tls_layer is record-like and has 'tls_handshake'.")


        if not record_data:
            logger.debug(f"Frame {packet.number}: Failed to obtain record_data.")
            # Final fallback from previous versions, directly on packet.tls if all else fails
            if hasattr(top_tls_layer, 'handshake_extensions_server_name'):
                sni_value = top_tls_layer.handshake_extensions_server_name
                logger.info(f"Frame {packet.number}: SNI found: {sni_value} (ULTIMATE FALLBACK on packet.tls.handshake_extensions_server_name)")
            return sni_value

        logger.debug(f"Frame {packet.number}: Record data obtained. Type: {type(record_data)}. Checking for handshake.")

        handshake_data = None
        if hasattr(record_data, 'tls_handshake'): # Check for PyShark attribute 'tls_handshake'
            handshake_data = record_data.tls_handshake
            logger.debug(f"Frame {packet.number}: Accessed 'tls_handshake' attribute from record_data.")
        elif 'tls.handshake' in record_data.field_names: # Check field name within record_data
            handshake_data = record_data.get_field_value('tls.handshake')
            logger.debug(f"Frame {packet.number}: Accessed 'tls.handshake' field via get_field_value from record_data.")
        else:
            logger.debug(f"Frame {packet.number}: Could not find 'tls_handshake' attribute or 'tls.handshake' field in record_data.")
            return sni_value # sni_value is None

        if not handshake_data:
            logger.debug(f"Frame {packet.number}: Handshake data is None.")
            return sni_value

        logger.debug(f"Frame {packet.number}: Handshake data obtained. Type: {type(handshake_data)}. Checking for extension.")

        extension_data = None
        if hasattr(handshake_data, 'tls_handshake_extension'): # Check for PyShark attribute
            extension_data = handshake_data.tls_handshake_extension
            logger.debug(f"Frame {packet.number}: Accessed 'tls_handshake_extension' attribute from handshake_data.")
        elif 'tls.handshake.extension' in handshake_data.field_names: # Check field name
            extension_data = handshake_data.get_field_value('tls.handshake.extension')
            logger.debug(f"Frame {packet.number}: Accessed 'tls.handshake.extension' field via get_field_value from handshake_data.")
        else:
            logger.debug(f"Frame {packet.number}: Could not find 'tls_handshake_extension' attribute or field in handshake_data.")
            return sni_value

        if not extension_data:
            logger.debug(f"Frame {packet.number}: Extension data is None.")
            return sni_value

        logger.debug(f"Frame {packet.number}: Extension data obtained. Type: {type(extension_data)}. Processing entries.")
        
        extensions_to_check = []
        if isinstance(extension_data, list):
            extensions_to_check.extend(extension_data)
        else:
            extensions_to_check.append(extension_data)

        for ext_entry in extensions_to_check:
            if hasattr(ext_entry, 'server_name_indication_extension'):
                sni_details_obj = ext_entry.server_name_indication_extension
                logger.debug(f"Frame {packet.number}: Accessed ext_entry.server_name_indication_extension.")
                if hasattr(sni_details_obj, 'extensions_server_name'):
                    sni_value = sni_details_obj.extensions_server_name
                    logger.info(f"Frame {packet.number}: SNI found: {sni_value} (via .extensions_server_name)")
                    break
                elif hasattr(sni_details_obj, 'tls_handshake_extensions_server_name'):
                    sni_value = sni_details_obj.tls_handshake_extensions_server_name
                    logger.info(f"Frame {packet.number}: SNI found: {sni_value} (via .tls_handshake_extensions_server_name)")
                    break
        
        if isinstance(sni_value, list): # Ensure it's not a list
            sni_value = sni_value[0] if sni_value else None

    except Exception as e:
        logger.error(f"Frame {packet.number}: General exception in _extract_sni_pyshark: {e}", exc_info=True)
        sni_value = None

    if sni_value is None:
        logger.debug(f"Frame {packet.number}: Final SNI extraction resulted in None.")
    else:
        logger.info(f"Frame {packet.number}: Final SNI value determined: {sni_value}")
    return sni_value

def _parse_with_pyshark(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Starting PCAP parsing with PyShark for: {file_path}")
    generated_records = 0
    cap = None  # Initialize cap to None for the finally block
    try:
        cap = pyshark.FileCapture(
            file_path,
            use_json=True,
            include_raw=True, # Keep for raw_summary, can be removed if raw_summary not critical
            keep_packets=False # Good for memory
        )
    except pyshark.capture.capture.TSharkNotFoundException as e_tshark:
        logger.error(f"PyShark TSharkNotFoundException: {e_tshark}. Ensure TShark is installed and in PATH.")
        raise RuntimeError(f"PyShark critical error: TShark not found.") from e_tshark
    except Exception as e_init:
        logger.error(f"PyShark error opening/initializing pcap file {file_path}: {e_init}")
        raise RuntimeError(f"PyShark failed to open or initialize {file_path}.") from e_init

    packet_count = 0
    try: # This is the outer try for iterating through the capture
        for packet in cap:
            if max_packets is not None and generated_records >= max_packets:
                logger.info(f"PyShark: Reached max_packets limit of {max_packets}.")
                break
            
            packet_count += 1
            # This is the inner try for processing a single packet
            try:
                timestamp = float(packet.sniff_timestamp)
                frame_number = int(packet.number)
                
                source_ip, destination_ip, source_port, destination_port, protocol, sni = \
                    None, None, None, None, None, None
                
                # Use highest_layer for a general summary, could be more specific if needed
                raw_summary = str(packet.highest_layer) if hasattr(packet, 'highest_layer') else 'N/A'
                
                ip_layer_obj = None
                # Check for IP layer first
                if hasattr(packet, 'ip'):
                    ip_layer_obj = packet.ip
                    if hasattr(ip_layer_obj, 'proto'):
                        protocol_num = int(ip_layer_obj.proto)
                        if protocol_num == 1: protocol = "ICMP"
                        elif protocol_num == 6: protocol = "TCP"
                        elif protocol_num == 17: protocol = "UDP"
                        else: protocol = str(protocol_num)
                    else:
                        logger.debug(f"Frame {frame_number}: IP layer missing 'proto' attribute.")
                elif hasattr(packet, 'ipv6'):
                    ip_layer_obj = packet.ipv6
                    if hasattr(ip_layer_obj, 'nxt'): # Next Header field in IPv6
                        protocol_num = int(ip_layer_obj.nxt)
                        if protocol_num == 6: protocol = "TCP"
                        elif protocol_num == 17: protocol = "UDP"
                        elif protocol_num == 58: protocol = "ICMPv6" # Protocol number for ICMPv6
                        else: protocol = str(protocol_num)
                    else:
                        logger.debug(f"Frame {frame_number}: IPv6 layer missing 'nxt' attribute.")
                
                if ip_layer_obj:
                    if hasattr(ip_layer_obj, 'src'): source_ip = str(ip_layer_obj.src)
                    if hasattr(ip_layer_obj, 'dst'): destination_ip = str(ip_layer_obj.dst)
                else: 
                    # Non-IP packet, yield what we have and continue
                    # Check if already yielded for this packet_count to avoid duplicates if other parts fail
                    if packet_count > generated_records : # ensure we don't double-count if other parts of try fail
                        desc = ', '.join([str(layer.layer_name) for layer in packet.layers])
                        yield PcapRecord(frame_number=frame_number, timestamp=timestamp, raw_packet_summary=f"L2: {desc}")
                        generated_records += 1
                    continue # Move to the next packet

                # Transport layer processing
                transport_layer_obj = None
                if protocol == "TCP" and hasattr(packet, 'tcp'):
                    transport_layer_obj = packet.tcp
                elif protocol == "UDP" and hasattr(packet, 'udp'):
                    transport_layer_obj = packet.udp

                if transport_layer_obj:
                    if hasattr(transport_layer_obj, 'srcport'): source_port = int(transport_layer_obj.srcport)
                    if hasattr(transport_layer_obj, 'dstport'): destination_port = int(transport_layer_obj.dstport)

                # SNI extraction
                if protocol == "TCP": # TLS is typically over TCP
                    sni = _extract_sni_pyshark(packet)
                elif protocol == "UDP": # Check for DTLS
                    # Check if 'dtls' layer exists OR if 'tls' layer exists on a common DTLS port (e.g., 4433)
                    # Note: PyShark might not always have a distinct 'dtls' layer name, might show as 'tls'
                    if hasattr(packet, 'dtls') or \
                       (hasattr(packet, 'tls') and destination_port in [443, 4433]): # Common DTLS/TLS-over-UDP ports
                         sni = _extract_sni_pyshark(packet)
                
                logger.debug(f"Frame {frame_number}: BEFORE PcapRecord: proto='{protocol}', sni='{sni}' (type: {type(sni)})")
                yield PcapRecord(
                    frame_number=frame_number, timestamp=timestamp,
                    source_ip=source_ip, destination_ip=destination_ip,
                    source_port=source_port, destination_port=destination_port,
                    protocol=protocol, sni=sni, raw_packet_summary=raw_summary
                )
                generated_records += 1

            # These are the 'except' blocks for the INNER try (single packet processing)
            except AttributeError as ae:
                logger.warning(f"Frame {packet_count}: Attribute error processing packet details: {ae}. Packet Layers: {packet.layers}")
            except Exception as e_pkt:
                logger.error(f"Frame {packet_count}: Error processing packet: {e_pkt}. Skipping.", exc_info=True)
            
            if packet_count > 0 and packet_count % 1000 == 0 :
                logger.info(f"PyShark: Scanned {packet_count} packets...")

    # These are the 'except' blocks for the OUTER try (capture iteration)
    except pyshark.capture.capture.TSharkCrashException as e_crash:
        logger.error(f"TShark crashed while processing {file_path}: {e_crash}")
        raise RuntimeError(f"TShark crashed, unable to process {file_path}.") from e_crash
    except Exception as e_cap_iter: # General errors during capture iteration
        logger.error(f"An error occurred during PyShark packet iteration in {file_path}: {e_cap_iter}", exc_info=True)
        # Optionally re-raise or handle as a critical failure for this parser
    
    # This 'finally' is for the OUTER try block
    finally:
        if cap: # Check if cap was successfully assigned before trying to close
            cap.close()
        logger.info(f"PyShark: Finished processing. Scanned {packet_count} packets, yielded {generated_records} records.")


# --- PCAPKit Parsing Logic (Simplified for brevity, as it's a fallback) ---
def _parse_with_pcapkit(file_path: str, max_packets: Optional[int]) -> Generator[PcapRecord, None, None]:
    logger.info(f"Attempting to parse with PCAPKit (fallback): {file_path}")
    logger.warning("PCAPKit fallback: SNI parsing is currently not implemented in this PcapKit path.")
    # ... (PCAPKit logic would go here, ensure it yields PcapRecord objects)
    # For now, let's make it yield nothing to demonstrate fallback completion if it were used.
    if False: # Keep pcapkit imports but don't run this code path unless fleshed out
        yield # This makes it a generator
    logger.info("PCAPKit: Processing complete (stubbed).")
    return
    # Actual PCAPKit implementation would be more complex, similar to PyShark's loop.


# --- Main Dispatcher ---
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
        except RuntimeError as e_pyshark_init: # Catch specific init errors from _parse_with_pyshark
            logger.warning(f"PyShark primary parser failed: {e_pyshark_init}")
            if not _USE_PCAPKIT:
                logger.error("PyShark failed and PCAPKit fallback is not available. Cannot parse file.")
                raise
            logger.info("Falling back to PCAPKit...")
            record_generator = None # Reset for PCAPKit
            parser_used = "PCAPKit_Fallback_After_PyShark_Error"
        # Catching a very broad Exception here might hide issues.
        # Consider more specific exceptions if PyShark can raise them.
        except Exception as e_pyshark_generic: 
            logger.error(f"An unexpected error occurred with PyShark: {e_pyshark_generic}", exc_info=True)
            if not _USE_PCAPKIT:
                logger.error("PyShark failed and PCAPKit fallback is not available.")
                raise
            logger.info("Falling back to PCAPKit due to unexpected PyShark error...")
            record_generator = None
            parser_used = "PCAPKit_Fallback_After_PyShark_Error"


    if record_generator is None and _USE_PCAPKIT:
        # This block runs if PyShark was not used OR if it failed and we need to fallback.
        if parser_used != "PCAPKit_Fallback_After_PyShark_Error": # Only log this if PCAPKit is primary attempt
             logger.info("PyShark not used or available. Attempting to parse with PCAPKit...")
        parser_used = "PCAPKit" # Or update if it was a fallback
        try:
            record_generator = _parse_with_pcapkit(file_path, max_packets)
        except FileNotFoundError: # Raised by pcapkit_extract if file not found
            logger.error(f"PCAPKit error: File not found at {file_path}")
            raise
        except Exception as e_pcapkit:
            logger.error(f"PCAPKit failed to process the file: {e_pcapkit}", exc_info=True)
            # If PyShark was already tried and failed, this means both failed.
            # If PyShark wasn't tried, this is the first failure.
            raise RuntimeError(f"PCAP parsing failed with {parser_used} for {file_path}.") from e_pcapkit
    
    if record_generator:
        logger.info(f"Collecting records using {parser_used}...")
        for record_idx, record in enumerate(record_generator): # Added enumerate for count
            records_list.append(record)
            if max_packets is not None and len(records_list) >= max_packets:
                # This log is now less critical as limit is primarily enforced in generators
                # logger.debug(f"Main dispatcher: Reached max_packets limit of {max_packets} during collection at record {record_idx + 1}.")
                break
        logger.info(f"Collected {len(records_list)} records using {parser_used}.")
    else:
        if not (_USE_PYSHARK and parser_used == "PyShark") and not (_USE_PCAPKIT and parser_used.startswith("PCAPKit")):
             # This case should ideally be caught by the initial check or specific parser failures.
             raise RuntimeError("No valid parser (PyShark or PCAPKit) was successfully initiated.")

    if not records_list:
        logger.warning(f"No records were parsed from '{file_path}' using {parser_used}. Returning an empty DataFrame.")
        # Create an empty DataFrame with the correct columns for schema consistency
        return pd.DataFrame(columns=[f.name for f in PcapRecord.__dataclass_fields__.values()])

    df = pd.DataFrame([asdict(r) for r in records_list])
    logger.info(f"Successfully parsed {len(df)} records into a DataFrame using {parser_used}.")
    return df

# Example Usage (keep for direct script execution and testing)
if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG, # Set to DEBUG to see all logs from this file
        format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s'
    )
    logger.info("Running PcapParser example from __main__")

    # For testing, you might want to point to the test PCAP file
    # Assuming tests/fixtures/ directory structure as per problem spec
    script_dir = Path(__file__).resolve().parent
    # This constructs a path like .../pcap-tool/src/pcap_tool/../../tests/fixtures/
    # Adjust if your script is run from a different working directory.
    # For __main__ it's usually simpler to assume the file is in current dir or specify full/relative path manually.
    
    # test_pcap_file = "tests/fixtures/mini.pcap" # Relative to project root if run from there
    # For simplicity in __main__, let's expect it in the same dir or use an absolute path
    test_pcap_file = "test_capture.pcapng" # A file you create for testing

    import os
    if not os.path.exists(test_pcap_file):
        logger.error(f"Test PCAP file '{test_pcap_file}' not found. Please create it or update path.")
        logger.info(f"You can create one using: tshark -F pcapng -w {test_pcap_file} -c 20")
    else:
        logger.info(f"Attempting to parse '{test_pcap_file}' with max_packets=5...")
        try:
            df_packets = parse_pcap(test_pcap_file, max_packets=5)
            print(f"\n--- DataFrame (first {min(len(df_packets), 5)} rows) ---")
            print(f"Total rows in DataFrame: {len(df_packets)}")
            if not df_packets.empty:
                try:
                    print(df_packets.head(min(len(df_packets), 5)).to_markdown(index=False))
                except Exception: # Handle if to_markdown is not available or fails
                    print(df_packets.head(min(len(df_packets), 5)))
            else:
                print("DataFrame is empty.")
        except Exception as e:
            logger.error(f"An error occurred in the example usage: {e}", exc_info=True)
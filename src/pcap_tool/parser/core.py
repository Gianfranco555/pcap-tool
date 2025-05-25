# src/pcap_tool/parser.py
from dataclasses import asdict
from typing import TYPE_CHECKING, List, Optional
from typing import (
    Generator,
    Any,
    IO,
    Iterator,
    Callable,
)
import logging
from pcap_tool.logging import get_logger
from ..core.config import settings
import pandas as pd
from pathlib import Path
import subprocess
import tempfile
import os
from math import ceil
from concurrent.futures import ProcessPoolExecutor

from ..exceptions import CorruptPcapError, ParserNotAvailable, PcapParsingError
from ..core.decorators import handle_parse_errors, log_performance
from ..heuristics.errors import detect_packet_error
from ..core.constants import (
    MAGIC_PCAP_LE,
    MAGIC_PCAP_BE,
    MAGIC_PCAPNG,
)

from ..models import PcapRecord, ParsedHandle
from ..parsers.factory import ParserFactory
from ..parsers.pyshark_parser import USE_PYSHARK
from ..parsers.pcapkit_parser import USE_PCAPKIT
from ..parsers.utils import _safe_int

if TYPE_CHECKING:
    from pyshark.packet.packet import Packet

logger = get_logger(__name__)

if not USE_PYSHARK and not USE_PCAPKIT:
    logger.error("Neither PyShark nor PCAPKit is available. PCAP parsing will not function.")

# --- PCAP validation constants are imported from pcap_tool.core.constants ---

def validate_pcap_file(filepath: str) -> bool:
    """Return ``True`` if ``filepath`` appears to be a valid PCAP/PCAPNG file."""

    path = Path(filepath)
    if not path.is_file():
        logger.warning("PCAP file does not exist: %s", filepath)
        return False
    try:
        with path.open("rb") as f:
            magic = f.read(4)
    except OSError as exc:
        logger.warning("Failed to read file %s: %s", filepath, exc)
        return False

    if magic in (MAGIC_PCAP_LE, MAGIC_PCAP_BE, MAGIC_PCAPNG):
        return True

    logger.warning("Invalid PCAP magic number %s for %s", magic.hex(), filepath)
    return False

def _ensure_path(file_like: Path | IO[bytes]) -> tuple[Path, bool]:
    """Return a file system Path for ``file_like``.

    If ``file_like`` is an open binary stream, its contents are written to a
    temporary file which is then returned.  The second element of the tuple
    indicates whether the caller should delete the path when finished.
    """
    if isinstance(file_like, (str, os.PathLike, Path)):
        return Path(file_like), False

    tmp = tempfile.NamedTemporaryFile(delete=False)

    try:
        tmp.write(file_like.read())
        tmp.flush()
    except Exception:
        try:
            tmp.close()
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        raise

    tmp.close()
    return Path(tmp.name), True


def _estimate_total_packets(path: Path) -> Optional[int]:
    """Estimate number of packets using ``capinfos -c`` if available."""

    commands = [["capinfos", "-c", str(path)]]
    env_path = os.environ.get("PCAP_TOOL_CAPINFOS_PATH")
    if env_path:
        commands.append([env_path, "-c", str(path)])

    for cmd in commands:
        logger.debug("Running packet count command: %s", " ".join(cmd))
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, check=True)
            logger.debug("count stdout: %s", proc.stdout.strip())
            logger.debug("count stderr: %s", proc.stderr.strip())
            for line in proc.stdout.splitlines():
                if "Number of packets" in line:
                    count_str = line.split(":", 1)[1].strip().replace(",", "")
                    suffix = count_str[-1].lower() if count_str else ""
                    multiplier = {
                        "k": 1_000,
                        "m": 1_000_000,
                        "g": 1_000_000_000,
                    }.get(suffix)
                    if multiplier:
                        try:
                            num = float(count_str[:-1].strip())
                            count = int(num * multiplier)
                        except ValueError:
                            logger.debug("Could not parse packet count: %s", count_str)
                            continue
                    else:
                        try:
                            count = int(count_str)
                        except ValueError:
                            logger.debug("Could not parse packet count: %s", count_str)
                            continue
                    logger.debug("Parsed packet count: %s", count)
                    return count
        except (subprocess.SubprocessError, FileNotFoundError) as exc:  # pragma: no cover - best effort only
            logger.debug("capinfos failed with %s: %s", cmd[0], exc)

    logger.debug("capinfos did not return a packet count")
    return None


def _get_record_generator(
    file_path: str,
    max_packets: Optional[int],
    *,
    start: int = 0,
    slice_size: Optional[int] = None,
) -> tuple[Optional[Generator[PcapRecord, None, None]], str]:
    """Return a generator yielding :class:`PcapRecord` objects."""
    available = ParserFactory.available_parsers()
    if not available:
        err_msg = "Neither PyShark nor PCAPKit is installed or available. Please install at least one."
        logger.critical(err_msg)
        raise ParserNotAvailable(err_msg)

    for parser_cls in available:
        parser = parser_cls()
        parser_name = parser_cls.__name__
        try:
            limit = slice_size if slice_size is not None else max_packets
            if slice_size is not None and max_packets is not None:
                limit = min(slice_size, max_packets)
            record_generator = parser.parse(
                file_path,
                limit,
                start=start,
                slice_size=slice_size,
            )
            return record_generator, parser_name
        except Exception as exc:
            logger.warning("%s failed: %s", parser_name, exc, exc_info=True)
            continue

    return None, "None"


def _process_slice(
    file_path: str,
    start_idx: int,
    slice_size: int,
    chunk_size: int,
) -> tuple[int, list[pd.DataFrame]]:
    """Worker helper to parse a slice of the pcap."""

    dfs = list(
        iter_parsed_frames(
            Path(file_path),
            chunk_size=chunk_size,
            max_packets=None,
            workers=0,
            _slice_start=start_idx,
            _slice_size=slice_size,
        )
    )
    first = dfs[0].iloc[0]["frame_number"] if dfs and not dfs[0].empty else start_idx + 1
    return first, dfs


@handle_parse_errors
@log_performance
def iter_parsed_frames(
    file_like: Path | IO[bytes],
    chunk_size: int = settings.chunk_size,
    on_progress: Callable[[int, Optional[int]], None] | None = None,
    max_packets: int | None = None,
    workers: int | None = settings.max_workers,
    _slice_start: int = 0,
    _slice_size: int | None = None,
) -> Iterator[pd.DataFrame]:

    """Yield parsed packets as ``pandas`` DataFrame chunks.

    Parameters
    ----------
    file_like:
        Path to the PCAP file or a binary file-like object.
    chunk_size:
        Number of rows per yielded ``DataFrame``. The default value comes from
        :class:`~pcap_tool.core.config.Settings` and can be adjusted via
        environment variables. Increase the size if sufficient memory is
        available for better performance, or decrease it if memory is
        constrained.
    on_progress:
        Optional callback receiving the current processed packet count and
        an estimated total packet count.
    max_packets:
        Maximum number of packets to process, or ``None`` for no limit.
    workers:
        Number of worker processes for parallel parsing. ``None`` uses up to
        four CPU cores, while ``0`` disables multiprocessing.
    """


    original_path = isinstance(file_like, (str, os.PathLike, Path))
    path, cleanup = _ensure_path(file_like)
    if not validate_pcap_file(str(path)):
        if cleanup:
            try:
                os.unlink(path)
            except OSError:
                pass
        logger.error("PCAP validation failed for %s", path)
        raise CorruptPcapError(f"Invalid or corrupt PCAP file: {path}")
    total_estimate = _estimate_total_packets(path)
    logger.debug("Total packet estimate from capinfos: %s", total_estimate)
    if total_estimate is not None:
        est_chunks = ceil(total_estimate / chunk_size)
        logger.debug(
            "Estimated chunks for chunk_size %s: %s", chunk_size, est_chunks
        )

    # Auto workers detection (cap at 4)
    if workers is None:
        cpu = os.cpu_count() or 1
        workers = min(cpu, 4)

    if _slice_start or _slice_size:
        workers = 0

    if (
        workers <= 1
        or not original_path
        or total_estimate is None
        or path.stat().st_size < 50 * 1024 * 1024
    ):
        record_generator, parser_used = _get_record_generator(
            str(path),
            max_packets,
            start=_slice_start,
            slice_size=_slice_size,
        )
        logger.info("Using parser backend: %s", parser_used)
    else:
        total_packets = total_estimate
        if max_packets is not None:
            total_packets = min(total_packets, max_packets)
        slice_size_packets = ceil(total_packets / workers)
        futures = []
        with ProcessPoolExecutor(max_workers=workers) as pool:
            start = 0
            while start < total_packets:
                size = min(slice_size_packets, total_packets - start)
                futures.append(
                    pool.submit(
                        _process_slice,
                        str(path),
                        start,
                        size,
                        chunk_size,
                    )
                )
                start += size
        results = [f.result() for f in futures]
        results.sort(key=lambda x: x[0])
        for _, dfs in results:
            for df in dfs:
                yield df
        if cleanup:
            try:
                os.unlink(path)
            except OSError:
                pass
        return

    if record_generator is None:
        logger.error("No valid parser (PyShark or PCAPKit) was successfully initiated or yielded records.")
        cols = [f.name for f in PcapRecord.__dataclass_fields__.values()] + [
            "packet_error_reason"
        ]
        logger.debug("Yielding empty DataFrame because no records were generated")
        yield pd.DataFrame(columns=cols)
        if cleanup:
            os.unlink(path)
        return

    rows: List[dict] = []
    count = 0
    next_callback = 100

    try:
        for record in record_generator:
            # logger.debug(f"Processing raw packet/record: {record}")
            processed_dict = asdict(record)
            processed_dict["packet_error_reason"] = detect_packet_error(processed_dict)
            # logger.debug(f"Appending processed packet to list: {processed_dict}")
            rows.append(processed_dict)
            count += 1
            if on_progress and count >= next_callback:
                on_progress(count, total_estimate)
                next_callback = count + 100
            if len(rows) >= chunk_size:
                if on_progress:
                    on_progress(count, total_estimate)
                df_chunk = pd.DataFrame(rows)
                # logger.debug(f"Yielding DataFrame chunk with shape: {df_chunk.shape}")
                yield df_chunk
                rows.clear()
            if max_packets is not None and count >= max_packets:
                break
    finally:
        if cleanup:
            try:
                os.unlink(path)
            except OSError:
                pass

    if rows:
        if on_progress:
            on_progress(count, total_estimate)
        df_chunk = pd.DataFrame(rows)
        # logger.debug(f"Yielding final DataFrame chunk with shape: {df_chunk.shape}")
        yield df_chunk
    elif count == 0:
        cols = [f.name for f in PcapRecord.__dataclass_fields__.values()] + [
            "packet_error_reason"
        ]
        # logger.debug("Yielding empty DataFrame at end because no packets were processed")
        yield pd.DataFrame(columns=cols)


@handle_parse_errors
@log_performance
def parse_pcap_to_df(
    file_like: Path | IO[bytes],
    chunk_size: int = settings.chunk_size,
    on_progress: Callable[[int, Optional[int]], None] | None = None,
    max_packets: int | None = None,
    workers: int | None = settings.max_workers,
) -> pd.DataFrame:

    """Parse ``file_like`` and return a single concatenated ``DataFrame``.

    ``chunk_size`` follows the same guidance as :func:`iter_parsed_frames` and
    may be tuned based on available memory.
    """


    logger.info(f"Attempting to parse PCAP file: {file_like}")
    logger.info(f"Effective _USE_PYSHARK: {USE_PYSHARK}, _USE_PCAPKIT: {USE_PCAPKIT}")

    chunks = list(
        iter_parsed_frames(
            file_like,
            chunk_size=chunk_size,
            on_progress=on_progress,
            max_packets=max_packets,
            workers=workers,
        )
    )
    logger.info("Number of DataFrame chunks produced: %s", len(chunks))
    total_packets = sum(len(c) for c in chunks)
    logger.info(f"Total processed packets collected for DataFrame: {total_packets}")
    if total_packets == 0:
        logger.warning("No packets were processed into the final list. DataFrame will be empty.")
    if not chunks:
        cols = [f.name for f in PcapRecord.__dataclass_fields__.values()] + [
            "packet_error_reason"
        ]
        return pd.DataFrame(columns=cols)
    df = pd.concat(chunks, ignore_index=True)
    logger.info(f"DataFrame created with shape: {df.shape if isinstance(df, pd.DataFrame) else 'Not a DataFrame'}")
    return df



@handle_parse_errors
@log_performance
def _parse_to_duckdb(
    file_like: Path | IO[bytes],
    db_path: str,
    *,
    chunk_size: int,
    on_progress: Callable[[int, Optional[int]], None] | None,
    workers: int | None,
):
    import duckdb

    conn = duckdb.connect(db_path)
    first = True
    for chunk in iter_parsed_frames(
        file_like,
        chunk_size=chunk_size,
        on_progress=on_progress,
        workers=workers,
    ):
        conn.register("tmp", chunk)
        if first:
            conn.execute("CREATE TABLE flows AS SELECT * FROM tmp")
            first = False
        else:
            conn.execute("INSERT INTO flows SELECT * FROM tmp")
        conn.unregister("tmp")
    return ParsedHandle("duckdb", db_path)


@handle_parse_errors
@log_performance
def _parse_to_arrow(
    file_like: Path | IO[bytes],
    out_dir: str,
    *,
    chunk_size: int,
    on_progress: Callable[[int, Optional[int]], None] | None,
    workers: int | None,
):
    import pyarrow as pa
    import pyarrow.ipc as ipc

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    idx = 0
    for chunk in iter_parsed_frames(
        file_like,
        chunk_size=chunk_size,
        on_progress=on_progress,
        workers=workers,
    ):
        table = pa.Table.from_pandas(chunk)
        with ipc.new_file(out_path / f"chunk_{idx:04d}.arrow", table.schema) as w:
            w.write(table)
        idx += 1
    return ParsedHandle("arrow", str(out_path))


@handle_parse_errors
@log_performance
def parse_pcap(
    file_like,
    *,
    output_uri: str | None = None,
    workers: int | None = settings.max_workers,
    chunk_size: int = settings.chunk_size,
    on_progress: Callable[[int, Optional[int]], None] | None = None,
) -> ParsedHandle:
    """Parse ``file_like`` and return a handle to the parsed flows."""

    logger.info(f"parse_pcap called with file_like: {file_like}")

    if output_uri is None:
        df = parse_pcap_to_df(
            file_like,
            chunk_size=chunk_size,
            on_progress=on_progress,
            workers=workers,
        )
        return ParsedHandle("memory", df)

    if output_uri.startswith("duckdb://"):
        db_path = output_uri[len("duckdb://") :]
        return _parse_to_duckdb(
            file_like,
            db_path,
            chunk_size=chunk_size,
            on_progress=on_progress,
            workers=workers,
        )
    if output_uri.startswith("arrow://"):
        dir_path = output_uri[len("arrow://") :]
        return _parse_to_arrow(
            file_like,
            dir_path,
            chunk_size=chunk_size,
            on_progress=on_progress,
            workers=workers,
        )

    raise PcapParsingError(
        "Unsupported output_uri scheme",
        context=str(output_uri),
        suggestion="Use 'duckdb://' or 'arrow://' URI schemes or omit output_uri for memory DataFrame.",
    )

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

import argparse
from pathlib import Path

from .parser import parse_pcap


def main():
    parser = argparse.ArgumentParser(description="PCAP utility")
    sub = parser.add_subparsers(dest="cmd", required=True)
    parse_cmd = sub.add_parser("parse", help="parse a pcap")
    parse_cmd.add_argument("pcap")
    parse_cmd.add_argument("--output", dest="output_uri", help="duckdb://file.db or arrow://dir")
    args = parser.parse_args()

    if args.cmd == "parse":
        handle = parse_pcap(Path(args.pcap), output_uri=args.output_uri)
        print(f"Parsed {handle.count()} flows")
        if args.output_uri is None:
            print(handle.as_dataframe().head())


if __name__ == "__main__":
    main()

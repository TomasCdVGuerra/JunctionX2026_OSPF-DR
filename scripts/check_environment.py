"""Verify the shared runtime; missing TShark affects PCAP scanning only."""
import sys
import argparse
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-tshark', action='store_true')
    args = parser.parse_args(argv)
    if sys.version_info[:2] != (3, 13):
        print(f"Python 3.13 required; found {sys.version.split()[0]}")
        return 1
    print(f"Python {sys.version.split()[0]}: OK")
    try:
        import cryptography
        import jsonschema
        import pandas
        import plotly
        import pydantic
        import pytest
        import rich
        import streamlit
    except ImportError as exc:
        print(f"Missing dependency: {exc}. Run python -m pip install -r requirements.txt")
        return 1
    print("Dashboard, models and test dependencies: OK")
    from scanner.network_scanner.parser.tshark_parser import (
        PcapParserError,
        find_tshark_binary,
    )
    try:
        binary = find_tshark_binary()
        result = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise PcapParserError(f'TShark could not start (exit {result.returncode}): {binary}')
        print(f"TShark: {binary} ({result.stdout.splitlines()[0] if result.stdout else 'OK'})")
    except (PcapParserError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"PCAP scanning unavailable: {exc}")
        if args.require_tshark:
            print('Install Wireshark/TShark or set TSHARK_PATH, then retry.')
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

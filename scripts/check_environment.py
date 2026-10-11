"""Verify the shared runtime; missing TShark affects PCAP scanning only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    if sys.version_info[:2] != (3, 13):
        print(f"Python 3.13 required; found {sys.version.split()[0]}")
        return 1
    print(f"Python {sys.version.split()[0]}: OK")
    try:
        import pandas
        import plotly
        import streamlit
        import jsonschema
        import pytest
        import cryptography
        import rich
        import pydantic
    except ImportError as exc:
        print(f"Missing dependency: {exc}. Run python -m pip install -r requirements.txt")
        return 1
    print("Dashboard, models and test dependencies: OK")
    from scanner.network_scanner.parser.tshark_parser import find_tshark_binary, PcapParserError
    try:
        print(f"TShark: {find_tshark_binary()}")
    except PcapParserError as exc:
        print(f"PCAP scanning unavailable: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

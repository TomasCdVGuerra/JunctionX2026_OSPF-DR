"""Tests verifying that the CLI entrypoint is safely disabled while preserving dormant CLI logic."""

from __future__ import annotations

import pytest

import main
from scanner.cli import build_cli_parser


def test_main_cli_entrypoint_is_temporarily_disabled(capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure invoking main.main() exits with code 2 and informs user to use the Streamlit dashboard."""
    exit_code = main.main()
    assert exit_code == 2

    captured = capsys.readouterr()
    assert "The QuantumTrace CLI is temporarily disabled." in captured.err
    assert "Run the Streamlit dashboard instead." in captured.err


def test_dormant_cli_module_preserved_for_future_reactivation() -> None:
    """Verify scanner.cli remains intact as dormant code for future reactivation."""
    parser = build_cli_parser()
    assert parser.prog == "quantumtrace"

    # Verify all expected arguments remain preserved in dormant parser
    actions = {action.dest for action in parser._actions}
    assert "source" in actions
    assert "cloud" in actions
    assert "pcap" in actions
    assert "all" in actions
    assert "output" in actions
    assert "verbose" in actions

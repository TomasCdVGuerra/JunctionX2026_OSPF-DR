"""Coordinate PCAP metadata extraction and protocol risk assessment."""
from __future__ import annotations

from pathlib import Path

from scanner.models import CryptoFinding
from scanner.network_scanner.analyser.cleartext_analyzer import analyze_cleartext
from scanner.network_scanner.analyser.ssh_analyzer import analyze_ssh
from scanner.network_scanner.analyser.tls_analyzer import analyze_tls
from scanner.network_scanner.parser.tshark_parser import parse_network_pcap


def scan(path: Path) -> list[CryptoFinding]:
    """Return assessed findings through a single metadata extraction call.

    Protocol analysers preserve each observation and its packet evidence.
    Missing parameters can still leave risks unknown after assessment.
    PcapParserError propagates to the caller when extraction fails.
    """
    path = Path(path)
    metadata = parse_network_pcap(str(path))

    findings = analyze_tls(metadata.get("tls_sessions", []), path)
    findings.extend(analyze_ssh(metadata.get("ssh_sessions", []), path))
    findings.extend(analyze_cleartext(metadata.get("cleartext_traffic", []), path))
    return findings

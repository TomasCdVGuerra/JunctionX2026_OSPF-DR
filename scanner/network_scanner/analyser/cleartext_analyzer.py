"""Analyze cleartext protocol observations from capture metadata."""
from __future__ import annotations

from pathlib import Path

from scanner.models import AssetType, CryptoFinding, QuantumRiskLevel
from scanner.network_scanner.analyser.risk_assessment import make_finding


def analyze_cleartext(entries: list[dict], path: Path) -> list[CryptoFinding]:
    """Assess plaintext application messages already identified by the parser.

    Entries come from detect_cleartext_traffic, which excludes encrypted
    transport and upgrade preambles. A port number alone is not evidence.
    """
    findings: list[CryptoFinding] = []

    for entry in entries:
        protocol = entry.get("protocol")
        if not isinstance(protocol, str) or not protocol.strip():
            continue
        protocol = protocol.strip()

        finding = make_finding(
            path,
            {**entry, "protocol": protocol},
            algorithm_name="Cleartext",
            rule_id="NETWORK-CLEARTEXT",
            observation="observed",
            asset_type=AssetType.PROTOCOL,
            protocol=protocol,
            risk_override=(
                QuantumRiskLevel.UNKNOWN,
                QuantumRiskLevel.CRITICAL,
                "Plaintext application traffic provides no transport "
                "confidentiality; its contents can be intercepted.",
                "Protect this protocol with an encrypted, authenticated "
                "transport such as TLS, or disable plaintext access.",
            ),
        )
        findings.append(finding)

    return findings

"""Assess TLS Hello evidence without promoting capabilities to negotiated use."""
from __future__ import annotations

from pathlib import Path

from scanner.models import AssetType, CryptoFinding, QuantumRiskLevel
from scanner.network_scanner.Analyser.risk_assessment import RiskAssessment, enrich_finding
from scanner.network_scanner.model_adapter import findings_from_metadata


def analyze_tls(entries: list[dict], path: Path) -> list[CryptoFinding]:
    """Enrich the adapter's TLS findings with primitive and protocol risks.

    The adapter keeps proposals, selections, unknown identifiers and packet
    provenance separate. A Hello selection does not prove handshake completion
    or reveal the certificate/key parameters absent from the capture metadata.
    """
    findings = findings_from_metadata({"tls_sessions": entries}, path)
    assessed: list[CryptoFinding] = []

    for finding in findings:
        override: RiskAssessment | None = None
        if finding.asset_type == AssetType.PROTOCOL:
            if finding.protocol in {"SSL 3.0", "TLS 1.0", "TLS 1.1"}:
                override = (
                    QuantumRiskLevel.UNKNOWN,
                    QuantumRiskLevel.CRITICAL,
                    f"{finding.protocol} is an obsolete protocol version that "
                    "must no longer be offered or negotiated; its version "
                    "alone does not determine quantum resistance.",
                    "Disable this version and require TLS 1.2 or TLS 1.3 "
                    "with an appropriate cryptographic configuration.",
                )
            else:
                override = (
                    QuantumRiskLevel.UNKNOWN,
                    QuantumRiskLevel.UNKNOWN,
                    f"The recorded TLS version {finding.protocol} alone does "
                    "not establish the security of the cipher, key exchange, "
                    "authentication or complete session.",
                    "Review the selected cryptographic primitives, their "
                    "parameters and handshake evidence before assessing "
                    "session security.",
                )
        assessed.append(enrich_finding(finding, risk_override=override))

    return assessed

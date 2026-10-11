"""Public network entrypoint, preserving protocol-specific assessments."""
from pathlib import Path

from scanner.models import CryptoFinding, Evidence
from scanner.network_scanner import pcap_scanner as network_scanner
from scanner.nist_references import nist_references_for_algorithm

NETWORK_ASSESSMENT_RULE_ID = "NETWORK-RISK-ASSESSMENT"


def scan(path: Path) -> list[CryptoFinding]:
    """Extract a capture once and annotate assessed results with references.

    TShark errors propagate to the dashboard instead of silently using a
    heuristic. Existing protocol assessments and packet evidence are preserved.
    """
    results = []
    for original in network_scanner.scan(Path(path)):
        finding = original.model_copy(deep=True)
        anchor = finding.evidence[0]
        references = nist_references_for_algorithm(
            finding.algorithm_name, finding.crypto_function, finding.mode,
        )
        finding.evidence.append(Evidence(
            file_path=anchor.file_path, packet_number=anchor.packet_number,
            rule_id=NETWORK_ASSESSMENT_RULE_ID,
            nist_standard="; ".join(references) or None,
            risk_reasoning=(
                f"Network assessment: quantum={finding.quantum_risk.value}; "
                f"classical={finding.classical_risk.value}. "
                + (anchor.risk_reasoning or "Protocol analysis; see packet evidence.")
            ),
        ))
        results.append(finding)
    return results

"""Ground-truth verification, report aggregate metrics, and cross-subsystem integration tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scanner.cbom import CBOMSerializer
from scanner.models import CryptoFinding, Evidence, QuantumRiskLevel
from scanner.report import (
    build_report_summary,
    calculate_hygiene_score,
    calculate_posture_status,
    calculate_quantum_risk_score,
    generate_summary_counts,
    group_by_algorithm,
    group_by_source,
)
from scanner.risk import enrich_finding, enrich_findings

EXPECTED_FINDINGS_PATH = Path(__file__).parent / "fixtures/expected_findings.json"


def load_expected_findings() -> dict[str, Any]:
    """Load hand-checked expected findings fixture."""
    return json.loads(EXPECTED_FINDINGS_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", load_expected_findings()["cases"], ids=lambda case: case["file"])
def test_reviewed_source_inventory(case):
    """Compare discovery and both risk axes with a manually explained oracle."""
    from collections import Counter

    from scanner.source_scanner import scan_file

    base = Path(__file__).resolve().parents[1] / "support-materials/sample-repos"
    findings = [enrich_finding(f) for f in scan_file(base / case["file"], base_dir=base)]
    actual = Counter((f.evidence[0].line_number, f.algorithm_name, f.crypto_function.value,
                      f.key_size, f.mode, f.quantum_risk.value, f.classical_risk.value)
                     for f in findings)
    expected = Counter(tuple(row) for row in case["expected"])
    assert actual == expected, {"reason": case["reason"], "missing": expected - actual, "unexpected": actual - expected}


def _create_mock_finding(
    algo: str,
    risk: QuantumRiskLevel | str,
    source_type: str = "source-code",
    key_size: int | None = None,
    mode: str | None = None,
) -> CryptoFinding:
    """Helper to generate valid CryptoFinding instances for tests."""
    risk_level = (
        risk if isinstance(risk, QuantumRiskLevel)
        else QuantumRiskLevel(risk.lower())
    )
    return CryptoFinding(
        algorithm_name=algo,
        key_size=key_size,
        mode=mode,
        source_type=source_type,  # type: ignore
        observation="observed",
        quantum_risk=risk_level,
        classical_risk=risk_level,
        evidence=[
            Evidence(
                file_path="mock_file.py",
                line_number=10,
                rule_id="mock-rule",
                risk_reasoning=f"{algo} test reasoning.",
            )
        ],
    )


# =========================================================================
# 15 Required Report Tests
# =========================================================================

def test_report_1_empty_findings():
    findings: list[CryptoFinding] = []
    counts = generate_summary_counts(findings)
    assert counts == {
        "Critical": 0,
        "Medium": 0,
        "Safe": 0,
        "Unknown": 0,
        "Total": 0,
    }
    assert calculate_quantum_risk_score(findings) == 0.0
    assert calculate_hygiene_score(findings) == 0
    assert calculate_posture_status(findings) == "NO_DATA"
    summary = build_report_summary(findings)
    assert summary["total_findings"] == 0
    assert summary["posture_status"] == "NO_DATA"
    assert summary["hygiene_score"] == 0


def test_report_2_all_critical():
    findings = [
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("MD5", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("Ed25519", QuantumRiskLevel.CRITICAL),
    ]
    counts = generate_summary_counts(findings)
    assert counts["Critical"] == 3
    assert counts["Total"] == 3
    assert calculate_quantum_risk_score(findings) == 100.0
    assert calculate_hygiene_score(findings) == 0
    assert calculate_posture_status(findings) == "FAILING"


def test_report_3_all_medium():
    findings = [
        _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM),
        _create_mock_finding("AES-128-CBC", QuantumRiskLevel.MEDIUM),
    ]
    counts = generate_summary_counts(findings)
    assert counts["Medium"] == 2
    assert counts["Total"] == 2
    assert calculate_quantum_risk_score(findings) == 30.0
    assert calculate_hygiene_score(findings) == 70
    assert calculate_posture_status(findings) == "AT_RISK"


def test_report_4_all_safe():
    findings = [
        _create_mock_finding("AES-256-GCM", QuantumRiskLevel.SAFE),
        _create_mock_finding("SHA-384", QuantumRiskLevel.SAFE),
        _create_mock_finding("ML-KEM-768", QuantumRiskLevel.SAFE),
    ]
    counts = generate_summary_counts(findings)
    assert counts["Safe"] == 3
    assert counts["Total"] == 3
    assert calculate_quantum_risk_score(findings) == 0.0
    assert calculate_hygiene_score(findings) == 100
    assert calculate_posture_status(findings) == "SECURE"


def test_report_5_mixed_findings():
    findings = [
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM),
        _create_mock_finding("AES-256-GCM", QuantumRiskLevel.SAFE),
        _create_mock_finding("CustomCipher", QuantumRiskLevel.UNKNOWN),
    ]
    counts = generate_summary_counts(findings)
    assert counts == {
        "Critical": 1,
        "Medium": 1,
        "Safe": 1,
        "Unknown": 1,
        "Total": 4,
    }
    # Exposure is measured over the three assessed quantum findings.
    assert calculate_quantum_risk_score(findings) == 43.33
    # Unassessed classical findings do not contribute verified hygiene.
    assert calculate_hygiene_score(findings) == 42
    assert calculate_posture_status(findings) == "FAILING"


def test_report_6_correct_totals():
    findings = [
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("SHA-256", QuantumRiskLevel.SAFE),
    ]
    counts = generate_summary_counts(findings)
    assert counts["Total"] == len(findings)
    assert counts["Critical"] + counts["Medium"] + counts["Safe"] + counts["Unknown"] == counts["Total"]


def test_report_7_correct_score_normalization():
    # 1 Critical, 1 Medium
    findings = [
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM),
    ]
    # (1.0 + 0.3) / 2 * 100 = 65.0
    score = calculate_quantum_risk_score(findings)
    assert score == 65.0
    assert 0.0 <= score <= 100.0


def test_report_8_no_division_by_zero():
    empty_list: list[Any] = []
    assert calculate_quantum_risk_score(empty_list) == 0.0
    assert calculate_hygiene_score(empty_list) == 0
    assert calculate_posture_status(empty_list) == "NO_DATA"


def test_report_9_correct_posture_status():
    # 1. Critical > 0 -> FAILING
    assert calculate_posture_status([_create_mock_finding("RSA", QuantumRiskLevel.CRITICAL)]) == "FAILING"

    # 2. No critical, medium > 0 -> AT_RISK
    assert calculate_posture_status([_create_mock_finding("AES-128", QuantumRiskLevel.MEDIUM)]) == "AT_RISK"

    # 3. Dict with quantum_vulnerable=True -> AT_RISK
    assert calculate_posture_status([{"quantum_risk": "safe", "quantum_vulnerable": True}]) == "AT_RISK"

    # 4. Only safe -> SECURE
    assert calculate_posture_status([_create_mock_finding("AES-256", QuantumRiskLevel.SAFE)]) == "SECURE"

    # 5. Empty -> NO_DATA
    assert calculate_posture_status([]) == "NO_DATA"


def test_report_10_correct_hygiene_score():
    findings = [
        _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM),
        _create_mock_finding("AES-256-GCM", QuantumRiskLevel.SAFE),
    ]
    # 100 - (0 * 100 + 1 * 30) / 2 = 100 - 15 = 85
    assert calculate_hygiene_score(findings) == 85


def test_report_11_stable_source_type_grouping():
    findings = [
        _create_mock_finding("RSA", QuantumRiskLevel.CRITICAL, source_type="network-capture"),
        _create_mock_finding("AES", QuantumRiskLevel.SAFE, source_type="source-code"),
        _create_mock_finding("KMS", QuantumRiskLevel.SAFE, source_type="cloud-posture"),
        _create_mock_finding("TLS", QuantumRiskLevel.SAFE, source_type="network-capture"),
    ]
    groups = group_by_source(findings)
    assert list(groups.keys()) == ["cloud-posture", "network-capture", "source-code"]
    assert groups["network-capture"] == 2
    assert groups["cloud-posture"] == 1
    assert groups["source-code"] == 1


def test_report_12_stable_algorithm_grouping():
    findings = [
        _create_mock_finding("AES-256", QuantumRiskLevel.SAFE),
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("AES-256", QuantumRiskLevel.SAFE),
        _create_mock_finding("SHA-256", QuantumRiskLevel.SAFE),
    ]
    groups = group_by_algorithm(findings)
    # Highest count first (AES-256: 2), then tie-break alphabetically (RSA-2048: 1, SHA-256: 1)
    keys = list(groups.keys())
    assert keys[0] == "AES-256"
    assert groups["AES-256"] == 2
    assert keys[1] == "RSA-2048"
    assert keys[2] == "SHA-256"


def test_report_13_json_serializability():
    findings = [
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM),
        _create_mock_finding("ML-KEM-768", QuantumRiskLevel.SAFE),
        _create_mock_finding("UnknownPrimitive", QuantumRiskLevel.UNKNOWN),
    ]
    summary = build_report_summary(findings)
    # Must serialize cleanly to JSON string without errors
    serialized = json.dumps(summary, indent=2)
    assert serialized is not None
    loaded = json.loads(serialized)
    assert loaded["total_findings"] == 4
    assert len(loaded["critical_findings"]) == 1
    assert len(loaded["medium_findings"]) == 1
    assert len(loaded["safe_findings"]) == 1
    assert len(loaded["unknown_findings"]) == 1


def test_report_14_pydantic_enum_handling():
    finding = _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM)
    assert isinstance(finding.quantum_risk, QuantumRiskLevel)
    counts = generate_summary_counts([finding])
    assert counts["Medium"] == 1
    score = calculate_quantum_risk_score([finding])
    assert score == 30.0


def test_report_15_missing_unknown_risk_handling():
    raw_dicts = [
        {"algorithm_name": "Test1", "quantum_risk": None},
        {"algorithm_name": "Test2"},
        {"algorithm_name": "Test3", "risk_rating": "unrecognized_level"},
    ]
    counts = generate_summary_counts(raw_dicts)
    assert counts["Unknown"] == 3
    assert counts["Total"] == 3
    assert counts["Critical"] == 0


# =========================================================================
# Integration & Ground Truth Verification Tests
# =========================================================================

def test_integration_dashboard_and_report_counts_agree():
    import dashboard

    findings = [
        _create_mock_finding("RSA-2048", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("AES-128-GCM", QuantumRiskLevel.MEDIUM),
        _create_mock_finding("AES-256-GCM", QuantumRiskLevel.SAFE),
    ]
    cbom = dashboard._build_cbom_from_findings(findings)
    df = dashboard.load_findings_dataframe(cbom)

    dashboard_counts = (
        df["Quantum Risk"]
        .value_counts()
        .reindex(["Critical", "Medium", "Safe", "Unknown"], fill_value=0)
        .to_dict()
    )
    report_counts = generate_summary_counts(findings)

    for tier in ("Critical", "Medium", "Safe", "Unknown"):
        assert dashboard_counts[tier] == report_counts[tier], f"Mismatch for {tier}"


def test_integration_cbom_generation_retains_enriched_risk():
    finding = CryptoFinding(
        algorithm_name="RSA-2048",
        key_size=2048,
        source_type="source-code",
        observation="observed",
        evidence=[
            Evidence(
                file_path="service.py",
                line_number=42,
                rule_id="src-rsa",
            )
        ],
    )
    enriched = enrich_finding(finding)

    serializer = CBOMSerializer()
    serializer.add_finding(enriched)
    cbom = serializer.document

    assert len(cbom["components"]) == 1
    comp = cbom["components"][0]
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}

    assert props["cryptotrace:riskRating"] == "critical"
    assert props["cryptotrace:quantumVulnerable"] == "true"
    assert "Shor" in comp["description"]


def test_integration_go_findings_retain_correct_risk_tiers():
    from scanner.source_scanner import scan_source_directory

    sample_go_dir = Path("support-materials/sample-repos/go")
    if not sample_go_dir.exists():
        sample_go_dir = Path("support-materials/source-code/go")
    if not sample_go_dir.exists():
        pytest.skip("Go sample directory not present in environment")

    findings = scan_source_directory(sample_go_dir)
    assert len(findings) > 0

    enriched = enrich_findings(findings)
    counts = generate_summary_counts(enriched)
    assert counts["Critical"] > 0, "Go samples contain Shor-vulnerable and broken primitives"
    assert counts["Safe"] > 0, "Go samples contain safe symmetric and HMAC primitives"


def test_integration_fallback_findings_visibly_marked():
    import dashboard

    # Fallback findings must carry 'fallback:' in Scanner source
    fallback_findings = dashboard._scan_source_file_fallback(Path("tests/test_dashboard.py"))
    dashboard._tag_findings_scanner_source(fallback_findings, "fallback: heuristic")

    for f in fallback_findings:
        assert dashboard._get_finding_scanner_source(f) == "fallback: heuristic"


def test_integration_no_scanner_result_silently_lost():
    findings = [
        _create_mock_finding("RSA-1024", QuantumRiskLevel.CRITICAL),
        _create_mock_finding("AES-128", QuantumRiskLevel.MEDIUM),
        _create_mock_finding("SHA-256", QuantumRiskLevel.SAFE),
    ]
    summary = build_report_summary(findings)
    total_categorized = (
        len(summary["critical_findings"])
        + len(summary["medium_findings"])
        + len(summary["safe_findings"])
        + len(summary["unknown_findings"])
    )
    assert total_categorized == len(findings)
    assert summary["total_findings"] == len(findings)

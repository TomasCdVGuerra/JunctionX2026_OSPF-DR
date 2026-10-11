"""Risk engine, report, dashboard and offline CBOM integration."""
import json
from pathlib import Path

import jsonschema

from dashboard import RISK_ORDER, _build_cbom_from_findings, load_findings_dataframe, scan_uploaded_files
from scanner.cbom import CBOMSerializer
from scanner.cloud_scanner import scan
from scanner.models import CryptoFinding, Evidence
from scanner.report import build_report_summary, calculate_posture_status
from scanner.risk import enrich_finding


def finding(name="AES", size=256, mode="GCM"):
    return CryptoFinding(
        algorithm_name=name, key_size=size, mode=mode,
        source_type="cloud-posture", observation="configured",
        evidence=[Evidence(file_path="input.json", json_path="$.Keys[0]",
                           rule_id="TEST-DISCOVERY", risk_reasoning="Original observation")],
    )


def test_unknown_inventory_does_not_claim_security():
    summary = build_report_summary([finding()])
    assert summary["posture_status"] == "INCOMPLETE"
    assert summary["hygiene_score"] == 0
    assert summary["quantum_coverage_percent"] == 0
    assert summary["classical_counts"]["Unknown"] == 1


def test_classical_critical_drives_posture_even_with_quantum_safe():
    evaluated = enrich_finding(finding(mode="ECB"))
    summary = build_report_summary([evaluated])
    assert summary["counts"]["Safe"] == 1
    assert summary["classical_counts"]["Critical"] == 1
    assert summary["posture_status"] == "FAILING"
    assert summary["hygiene_score"] == 0


def test_quantum_critical_does_not_become_classical_critical():
    evaluated = enrich_finding(finding("RSA", 2048, None))
    summary = build_report_summary([evaluated])
    assert summary["counts"]["Critical"] == 1
    assert summary["classical_counts"]["Safe"] == 1
    assert summary["posture_status"] == "FAILING"
    assert summary["hygiene_score"] == 100


def test_unknown_does_not_dilute_assessed_exposure():
    critical = enrich_finding(finding("RSA", 2048, None))
    summary = build_report_summary([critical, finding("Future", None, None)])
    assert summary["risk_score"] == 100
    assert summary["quantum_coverage_percent"] == 50
    assert summary["hygiene_score"] == 50
    assert calculate_posture_status([enrich_finding(finding()), finding()]) == "INCOMPLETE"


def test_cbom_preserves_engine_reasoning_risks_recommendation_and_evidence():
    evaluated = enrich_finding(finding(mode="ECB"))
    for value in (evaluated, evaluated.to_dict()):
        serializer = CBOMSerializer()
        serializer.add_finding(value)
        component = serializer.document["components"][0]
        properties = {p["name"]: p["value"] for p in component["properties"]}
        assert "Risco clássico (critical)" in component["description"]
        assert properties["cryptotrace:classical_risk"] == "critical"
        assert properties["cryptotrace:riskRating"] == "safe"
        assert properties["cryptotrace:recommendation"] == evaluated.recommendation
        assert json.loads(properties["cryptotrace:evidence"]) == evaluated.to_dict()["evidence"]


def test_dashboard_enriches_real_cloud_and_exports_valid_cbom():
    root = Path(__file__).resolve().parents[1]
    originals = scan(root / "support-materials" / "cloud-posture")
    before = [f.model_dump() for f in originals]
    cbom = _build_cbom_from_findings(originals)
    assert [f.model_dump() for f in originals] == before
    assert len(cbom["components"]) == 99
    schema = json.loads((root / "tests/fixtures/bom-1.6.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(cbom, schema)
    dataframe = load_findings_dataframe(cbom)
    assert (dataframe["Quantum Risk"] == "Unknown").sum() == 19
    risk_options = [risk for risk in RISK_ORDER if risk in set(dataframe["Quantum Risk"])]
    assert "Unknown" in risk_options
    assert len(dataframe[dataframe["Quantum Risk"].isin(risk_options)]) == 99
    assert (dataframe["Quantum Risk"] == "Critical").any()
    assert (dataframe["Classical Risk"] == "Critical").any()
    assert (dataframe["Recommendation"] != "unknown").all()
    assert dataframe["Description"].str.contains("Risco quântico").all()
    assert (dataframe["Rule ID"] != "unknown").all()
    assert (dataframe["Matched Snippet"] != "unknown").all()
    assert (dataframe["JSON Path"] != "N/A").all()
    assert (dataframe["Line Number"] == "N/A").all()
    assert (dataframe["Packet Number"] == "N/A").all()


def test_uploaded_cloud_uses_same_enrichment_pipeline():
    class Upload:
        name = "kms.json"
        def getvalue(self):
            return b'{"Keys": [{"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"}]}'
    cbom, warnings = scan_uploaded_files([Upload()])
    assert not warnings
    row = load_findings_dataframe(cbom).iloc[0]
    assert row["Quantum Risk"] == "Critical"
    assert row["Classical Risk"] == "Safe"
    assert "ML-DSA" in row["Recommendation"]

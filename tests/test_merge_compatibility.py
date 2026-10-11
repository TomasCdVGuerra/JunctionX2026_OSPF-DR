"""Regression coverage for CBOM assessment preservation after the merge."""
from scanner.cbom import CBOMSerializer
from dashboard import _report_findings_from_cbom, load_findings_dataframe


def test_export_preserves_explicit_unknown_without_assuming_safe():
    serializer = CBOMSerializer()
    serializer.add_finding({
        "algorithm_name": "RSA-2048", "quantum_risk": "critical",
        "classical_risk": "unknown",
    })
    props = {p["name"]: p["value"] for p in serializer.document["components"][0]["properties"]}
    assert props["cryptotrace:classicalRisk"] == "unknown"
    assert props["cryptotrace:classical_risk"] == "unknown"
    assert _report_findings_from_cbom(serializer.document)[0]["classical_risk"] == "unknown"


def test_current_unknown_takes_precedence_over_legacy_safe():
    row = load_findings_dataframe({"components": [{
        "name": "RSA", "properties": [
            {"name": "cryptotrace:classicalRisk", "value": "Safe"},
            {"name": "cryptotrace:classical_risk", "value": "unknown"},
        ],
    }]}).iloc[0]
    assert row["Classical Risk"] == "Unknown"

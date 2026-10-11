"""Acceptance checks for exposure, native exports and explicit scan failures."""
import json
from pathlib import Path
from unittest.mock import MagicMock

import jsonschema
import pytest

import dashboard
from scanner.cbom import CBOMSerializer
from scanner.models import CryptoFinding, Evidence
from scanner.report import build_report_summary
from scanner.source_scanner import scan_file, scan_source_directory


def finding(**changes):
    return CryptoFinding(algorithm_name="AES", source_type="source-code",
                         observation="declared", evidence=[Evidence(file_path="example.py", rule_id="test")],
                         **changes)


@pytest.mark.parametrize("tiers,score,coverage", [
    (["critical", "safe", "unknown"], "50.00/100", "66.67%"),
    (["unknown"], "N/A", "0.00%"),
    (["safe"], "0.00/100", "100.00%"),
])
def test_exposure_display_distinguishes_zero_risk_from_zero_coverage(monkeypatch, tiers, score, coverage):
    import pandas as pd
    findings = [finding(quantum_risk=tier) for tier in tiers]
    frame = pd.DataFrame({"Quantum Risk": [tier.capitalize() for tier in tiers],
                          "Classical Risk": ["Unknown"] * len(tiers),
                          "Quantum Vulnerable": [str(tier == "critical") for tier in tiers]})
    mock_st = MagicMock()
    rows = []
    def columns(count):
        row = [MagicMock() for _ in range(count)]
        rows.append(row)
        return row
    mock_st.columns.side_effect = columns
    monkeypatch.setattr(dashboard, "st", mock_st)
    summary = build_report_summary(findings)
    dashboard._render_metrics(frame, summary)
    rows[0][0].metric.assert_called_once_with("Quantum Risk Score", score)
    rows[0][1].metric.assert_called_once_with("Quantum Assessment Coverage", coverage)
    assert summary["classical_coverage_percent"] == 0


@pytest.mark.parametrize("asset,params,native", [
    ("algorithm", {"key_size": 256, "mode": "GCM", "crypto_function": "encrypt"},
     {"assetType": "algorithm", "algorithmProperties": {"parameterSetIdentifier": "256", "mode": "gcm", "cryptoFunctions": ["encrypt"]}}),
    ("key", {"key_size": 2048}, {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "key", "size": 2048}}),
    ("certificate", {}, {"assetType": "certificate"}),
    ("protocol", {"protocol": "TLS"}, {"assetType": "protocol", "protocolProperties": {"type": "tls"}}),
])
def test_native_cbom_metadata_preserves_explicit_contract(asset, params, native):
    serializer = CBOMSerializer()
    original = finding(asset_type=asset, library="cryptography", **params)
    serializer.add_finding(original)
    component = serializer.document["components"][0]
    assert component["cryptoProperties"] == native
    assert {p["name"]: p["value"] for p in component["properties"]}["cryptotrace:library"] == "cryptography"
    schema = json.loads((Path(__file__).parent / "fixtures/bom-1.6.schema.json").read_text())
    jsonschema.validate(serializer.document, schema)
    assert original.quantum_risk.value == "unknown"


def test_unknown_key_size_not_exported_as_security_strength():
    serializer = CBOMSerializer()
    serializer.add_finding(finding())
    algorithm = serializer.document["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert "parameterSetIdentifier" not in algorithm
    assert "classicalSecurityLevel" not in algorithm
    assert "nistQuantumSecurityLevel" not in algorithm


@pytest.mark.parametrize("filename,content", [("broken.py", "def broken(:"), ("Broken.java", "\x00")])
def test_failed_source_upload_visible_and_other_files_preserved(filename, content):
    class Upload:
        def __init__(self, name, body):
            self.name, self.body = name, body
        def getvalue(self):
            return self.body.encode()
    cbom, warnings = dashboard.scan_uploaded_files([
        Upload(filename, content), Upload("valid.py", "import hashlib\nhashlib.sha384(data)")])
    assert len(cbom["components"]) == 1
    assert any(f"Error scanning {filename}:" in warning for warning in warnings)
    assert not any("fallback" in warning.lower() for warning in warnings)


def test_directory_errors_collected_without_discarding_valid_results(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:")
    (tmp_path / "valid.py").write_text("import hashlib\nhashlib.sha384(data)")
    errors = []
    assert len(scan_source_directory(tmp_path, errors=errors)) == 1
    assert len(errors) == 1 and "broken.py" in errors[0]
    with pytest.raises(ValueError, match="Cannot parse"):
        scan_file(tmp_path / "broken.py")


def test_library_metadata_survives_dashboard_and_csv():
    path = Path(__file__).resolve().parents[1] / "support-materials/sample-repos/java/BatchExporter.java"
    cbom = dashboard._build_cbom_from_findings(scan_file(path))
    frame = dashboard.load_findings_dataframe(cbom)
    assert set(frame["Library / API"]) == {"javax.crypto.Cipher", "javax.crypto.spec.SecretKeySpec"}
    assert "javax.crypto.Cipher" in frame.to_csv(index=False)


def test_streamlit_renders_score_and_coverage_independent_of_filter():
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "dashboard.py"))
    app.session_state["cbom"] = dashboard._build_cbom_from_findings([
        finding(key_size=128), finding(key_size=256), finding()])
    app.session_state["cbom_source"] = "Acceptance example"
    app.run(timeout=20)
    assert not app.exception
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Quantum Risk Score"] == "15.00/100"
    assert metrics["Quantum Assessment Coverage"] == "66.67%"
    quantum_filter = next(widget for widget in app.multiselect if widget.label == "Quantum risk")
    quantum_filter.set_value(["Safe"])
    app.run(timeout=20)
    assert not app.exception
    assert {metric.label: metric.value for metric in app.metric} == metrics
    assert len(app.dataframe[0].value) == 1
    assert "Library / API" in app.dataframe[0].value.columns

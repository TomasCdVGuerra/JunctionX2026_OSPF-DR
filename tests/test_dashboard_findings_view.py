"""Overview selection preserves detailed evidence and full exports."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pandas as pd
import pytest

import dashboard
from scanner.models import CryptoFinding, Evidence


@pytest.mark.parametrize("location,expected", [
    ({"Line Number": 12}, "Line 12"),
    ({"Packet Number": 92}, "Packet 92"),
    ({"JSON Path": "$.Keys[0]"}, "$.Keys[0]"),
    ({"Line Number": "unknown", "Packet Number": "N/A"}, "N/A"),
])
def test_location_uses_recorded_source_metadata(location, expected):
    assert dashboard._finding_location(location) == expected


def inventory():
    findings = [CryptoFinding(
        algorithm_name="AES", key_size=256, mode="GCM", source_type="source-code",
        observation="declared", library="cryptography", crypto_function="encrypt",
        evidence=[Evidence(file_path="encrypt.py", line_number=12, rule_id="test-aes",
                           matched_snippet="AESGCM(KEY)")]),
        CryptoFinding(algorithm_name="RSA", key_size=2048, source_type="source-code",
                      observation="declared", evidence=[Evidence(file_path="keys.py", line_number=8,
                                                                  rule_id="test-rsa")])]
    return dashboard._build_cbom_from_findings(findings)


def mocked_ui(monkeypatch, rows):
    ui = MagicMock()
    ui.session_state = {}
    ui.multiselect.side_effect = lambda label, options, default: default
    ui.text_input.return_value = ""
    ui.button.return_value = False
    ui.columns.side_effect = lambda count: [MagicMock() for _ in range(count if isinstance(count, int) else len(count))]
    ui.dataframe.return_value = SimpleNamespace(selection=SimpleNamespace(rows=rows))
    monkeypatch.setattr(dashboard, "st", ui)
    return ui


def test_selection_shows_correct_finding_without_narrowing_exports(monkeypatch):
    cbom = inventory()
    ui = mocked_ui(monkeypatch, [0])
    details = MagicMock()
    monkeypatch.setattr(dashboard, "_render_finding_details", details)
    dashboard.render_dashboard(cbom)
    row, shown_cbom = details.call_args.args
    assert row["Algorithm"] == "RSA" and row["Source Path"] == "keys.py"
    assert shown_cbom is cbom
    tables = ui.dataframe.call_args_list
    overview = tables[0].args[0].data
    assert list(overview.columns) == ["Algorithm", "Quantum Risk", "Classical Risk", "Source", "Location", "Observation"]
    assert "Matched Snippet" in tables[1].args[0].data.columns
    csv = next(call.kwargs["data"] for call in ui.download_button.call_args_list
               if call.kwargs["file_name"] == "quantumtrace_findings.csv")
    from io import BytesIO
    exported = pd.read_csv(BytesIO(csv))
    assert len(exported) == 2
    assert {"Matched Snippet", "Recommendation", "Library / API", "NIST References", "BOM Reference"} <= set(exported.columns)
    assert "AESGCM(KEY)" in exported["Matched Snippet"].values


def test_filter_change_resets_selection_identity(monkeypatch):
    cbom = inventory()
    ui = mocked_ui(monkeypatch, [])
    dashboard.render_dashboard(cbom)
    first_key = ui.dataframe.call_args_list[0].kwargs["key"]
    ui.dataframe.reset_mock()
    ui.multiselect.side_effect = lambda label, options, default: ["Safe"] if label == "Quantum risk" else default
    dashboard.render_dashboard(cbom)
    assert ui.dataframe.call_args_list[0].kwargs["key"] != first_key
    assert len(ui.dataframe.call_args_list[0].args[0].data) == 1


def test_detail_view_contains_assessment_action_and_full_evidence(monkeypatch):
    cbom = inventory()
    row = dashboard.load_findings_dataframe(cbom).iloc[0]
    ui = mocked_ui(monkeypatch, [])
    dashboard._render_finding_details(row, cbom)
    text = [call.args[0] for call in ui.write.call_args_list]
    assert row["Recommendation"] in text
    assert any("Grover" in value for value in text)
    assert any("AES" in value for value in text)
    ui.code.assert_called_once_with("AESGCM(KEY)", language=None, wrap_lines=True)
    assert ui.json.call_args_list[0].args[0]["Rule ID"] == "test-aes"
    assert ui.json.call_args_list[0].args[0]["Description"] == row["Description"]
    assert ui.json.call_args_list[1].args[0] == cbom["components"][0]


def test_cloud_signature_evidence_highlights_recorded_field_without_subject_key_inference(monkeypatch):
    import json
    resource = {"KeyAlgorithm": "RSA_2048", "SignatureAlgorithm": "SHA256WITHRSA"}
    cbom = dashboard._build_cbom_from_findings([CryptoFinding(
        algorithm_name="SHA256WITHRSA", source_type="cloud-posture", observation="configured",
        crypto_function="sign", evidence=[Evidence(file_path="acm_certificates.json",
            json_path="$.Certificates[0].SignatureAlgorithm", rule_id="AWS-ACM-SIGNATURE",
            matched_snippet=json.dumps(resource))])])
    row = dashboard.load_findings_dataframe(cbom).iloc[0]
    assert row["Classical Risk"] == "Unknown"
    ui = mocked_ui(monkeypatch, [])
    dashboard._render_finding_details(row, cbom)
    focused = json.loads(ui.code.call_args_list[0].args[0])
    assert focused == {"SignatureAlgorithm": "SHA256WITHRSA"}
    assert json.loads(ui.code.call_args_list[1].args[0]) == resource
    assert any("issuer" in call.args[0] for call in ui.caption.call_args_list)


def test_focused_evidence_does_not_invent_missing_fields():
    row = {"Source Type": "cloud-posture", "JSON Path": "$.Certificates[0].SignatureAlgorithm"}
    assert dashboard._focused_cloud_evidence(row, '{"KeyAlgorithm":"RSA_2048"}') is None
    assert dashboard._focused_cloud_evidence(row, 'not JSON') is None

"""Prioritization and per-input scan coverage preserve the complete inventory."""
import json

import pandas as pd

import dashboard


class MockUploadedFile:
    def __init__(self, name, content):
        self.name = name
        self.content = content.encode("utf-8")

    def getvalue(self):
        return self.content


def test_both_axes_determine_priority_without_changing_ratings():
    frame = pd.DataFrame([
        {"Algorithm": "safe", "Quantum Risk": "Safe", "Classical Risk": "Safe"},
        {"Algorithm": "unresolved", "Quantum Risk": "Safe", "Classical Risk": "Unknown"},
        {"Algorithm": "medium", "Quantum Risk": "Medium", "Classical Risk": "Unknown"},
        {"Algorithm": "classical-critical", "Quantum Risk": "Safe", "Classical Risk": "Critical"},
        {"Algorithm": "quantum-critical", "Quantum Risk": "Critical", "Classical Risk": "Unknown"},
    ])
    sorted_frame = dashboard._prioritize_findings(frame)
    assert sorted_frame.Algorithm.tolist() == ["classical-critical", "quantum-critical", "medium", "unresolved", "safe"]
    pd.testing.assert_frame_equal(sorted_frame.sort_index(), frame)


def test_action_groups_count_observations_and_keep_priorities_separate():
    frame = pd.DataFrame([
        {"Algorithm": "RSA", "Quantum Risk": "Critical", "Classical Risk": "Unknown",
         "Recommendation": "Migrate", "Source Path": "one.json"},
        {"Algorithm": "RSA", "Quantum Risk": "Critical", "Classical Risk": "Safe",
         "Recommendation": "Migrate", "Source Path": "two.json"},
        {"Algorithm": "AES", "Quantum Risk": "Medium", "Classical Risk": "Safe",
         "Recommendation": "Migrate", "Source Path": "two.json"},
        {"Algorithm": "other", "Quantum Risk": "Unknown", "Classical Risk": "Unknown",
         "Recommendation": "unknown", "Source Path": "three.json"},
    ])
    actions = dashboard._priority_actions(frame)
    assert actions.Priority.tolist() == ["Critical", "Medium", "Unresolved"]
    assert actions.Findings.tolist() == [2, 1, 1]
    assert actions.iloc[0].Sources == "one.json, two.json"
    assert "Collect missing" in actions.iloc[2].Action


def test_invalid_cloud_does_not_hide_valid_file_and_status_survives_cbom_export():
    from pathlib import Path
    import jsonschema
    outcomes = []
    cbom, warnings = dashboard.scan_uploaded_files([
        MockUploadedFile("duplicate.json", "{bad"),
        MockUploadedFile("duplicate.json", '{"Keys": []}'),
        MockUploadedFile("key.json", json.dumps({"Keys": [{"KeySpec": "RSA_2048", "KeyId": "test"}]})),
    ], outcomes=outcomes)
    assert cbom is not None
    assert [row["Status"] for row in outcomes] == ["Failed", "No detections", "With findings"]
    assert [row["Input"] for row in outcomes] == [1, 2, 3]
    assert len(warnings) == 1 and "duplicate.json" in warnings[0]
    assert outcomes[0]["Error"] and outcomes[1]["Findings"] == 0
    assert outcomes[2]["Findings"] == len(cbom["components"])
    restored = json.loads(json.dumps(cbom))
    schema = json.loads((Path(__file__).parent / "fixtures/bom-1.6.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(restored, schema)
    raw = dashboard._extract_property(restored["metadata"]["properties"], "cryptotrace:scanOutcomes")
    assert json.loads(raw) == outcomes


def test_empty_scan_retains_outcome_without_claiming_safety():
    outcomes = []
    cbom, _ = dashboard.scan_uploaded_files([MockUploadedFile("empty.py", "x = 1")], outcomes=outcomes)
    assert cbom is None
    assert outcomes[0]["Status"] == "No detections"
    assert outcomes[0]["Scanner"].startswith("real:")


def test_invalid_json_is_failed_even_when_using_a_fallback(monkeypatch):
    monkeypatch.setattr(dashboard, "_get_cloud_scanner", lambda: None)
    outcomes = []
    cbom, warnings = dashboard.scan_uploaded_files([MockUploadedFile("bad.json", "{bad")], outcomes=outcomes)
    assert cbom is None and len(warnings) == 1
    assert outcomes[0]["Status"] == "Failed"
    assert outcomes[0]["Scanner"] == "FALLBACK heuristic"


def test_source_parse_failure_is_distinct_from_no_detections():
    outcomes = []
    cbom, warnings = dashboard.scan_uploaded_files([
        MockUploadedFile("bad.py", "def broken(:"),
        MockUploadedFile("empty.py", "x = 1"),
    ], outcomes=outcomes)
    assert cbom is None and len(warnings) == 1
    assert [row["Status"] for row in outcomes] == ["Failed", "No detections"]


def test_bundled_scan_uses_relative_paths_and_isolates_bad_inputs(tmp_path):
    folder = tmp_path / "cloud-posture"
    folder.mkdir()
    (folder / "broken.json").write_text("invalid", encoding="utf-8")
    (folder / "empty.json").write_text('{"Keys": []}', encoding="utf-8")
    outcomes = []
    cbom, warnings = dashboard.scan_bundled_data(tmp_path, outcomes=outcomes)
    assert cbom is None and len(warnings) == 1
    assert [row["File"] for row in outcomes] == ["cloud-posture/broken.json", "cloud-posture/empty.json"]
    assert [row["Status"] for row in outcomes] == ["Failed", "No detections"]


def test_streamlit_shows_file_coverage_even_without_findings():
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    outcomes = []
    cbom, warnings = dashboard.scan_uploaded_files([
        MockUploadedFile("bad.py", "def broken(:"),
        MockUploadedFile("empty.py", "x = 1"),
    ], outcomes=outcomes)
    app = AppTest.from_file(str(Path(dashboard.__file__)))
    app.session_state["cbom"] = cbom
    app.session_state["scan_outcomes"] = outcomes
    app.session_state["scan_warnings"] = warnings
    app.run(timeout=20)
    assert not app.exception
    assert app.dataframe[0].value.Status.tolist() == ["Failed", "No detections"]


def test_duplicate_names_keep_input_identity_in_cbom_table_and_action_groups():
    uploads = [MockUploadedFile("key.json", '{"Keys": [{"KeySpec": "RSA_2048"}]}') for _ in range(2)]
    cbom, warnings = dashboard.scan_uploaded_files(uploads)
    assert cbom is not None and not warnings
    frame = dashboard.load_findings_dataframe(cbom)
    assert frame["Input ID"].tolist() == ["1", "2"]
    assert frame["Source Path"].tolist() == ["key.json", "key.json"]
    assert dashboard._compact_findings_dataframe(frame).Source.tolist() == ["#1 key.json", "#2 key.json"]
    assert dashboard._priority_actions(frame).iloc[0].Sources == "#1 key.json, #2 key.json"
    assert frame["BOM Reference"].nunique() == 2
    restored = dashboard.load_findings_dataframe(json.loads(json.dumps(cbom)))
    assert restored["Input ID"].tolist() == ["1", "2"]
    assert "Input ID" in restored.to_csv(index=False)


def test_input_identity_preserves_separate_policy_catalogue_evidence():
    from pathlib import Path

    path = Path(dashboard.__file__).parent / "support-materials/cloud-posture/load_balancer_listeners.json"
    cbom, warnings = dashboard.scan_uploaded_files([MockUploadedFile(path.name, path.read_text(encoding="utf-8"))])
    assert cbom is not None and not warnings
    reviewed = 0
    for component in cbom["components"]:
        evidence = json.loads(dashboard._extract_property(component["properties"], "cryptotrace:evidence"))
        for item in evidence:
            if item["rule_id"] in {"AWS-ELB-POLICY-CIPHER", "AWS-ELB-POLICY-TLS-VERSION"}:
                assert Path(item["file_path"]).name == "elb_policies.json"
                assert item["file_path"] != path.name
                reviewed += 1
    assert reviewed > 0


def test_partial_scan_does_not_replace_known_critical_posture():
    from scanner.report import build_report_summary
    cbom, _ = dashboard.scan_uploaded_files([
        MockUploadedFile("key.json", '{"Keys": [{"KeySpec": "RSA_2048"}]}'),
        MockUploadedFile("bad.json", "{bad"),
    ])
    coverage = dashboard.summarize_scan_coverage(dashboard._scan_outcomes(cbom))
    assert coverage["status"] == "Partial" and coverage["failed_inputs"] == 1
    assert build_report_summary(dashboard._report_findings_from_cbom(cbom))["posture_status"] == "FAILING"


def test_streamlit_partial_scan_warning_remains_with_safe_findings_and_empty_filters():
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    cbom, _ = dashboard.scan_uploaded_files([
        MockUploadedFile("safe.json", '{"Region": "eu-west-1", "Keys": [{"KeySpec": "SYMMETRIC_DEFAULT"}]}'),
        MockUploadedFile("bad.json", "{bad"),
    ])
    assert cbom is not None
    app = AppTest.from_file(str(Path(dashboard.__file__)))
    app.session_state["cbom"] = json.loads(json.dumps(cbom))
    app.run(timeout=20)
    assert not app.exception
    assert next(metric.value for metric in app.metric if metric.label == "Input Scan Status") == "Partial"
    assert any("ANALYSIS PARTIAL" in warning.value for warning in app.warning)
    assert next(metric.value for metric in app.metric if metric.label == "Quantum Risk Score") == "0.00/100"
    next(widget for widget in app.multiselect if widget.label == "Quantum risk").set_value([])
    app.run(timeout=20)
    assert not app.exception
    assert any("ANALYSIS PARTIAL" in warning.value for warning in app.warning)


def test_legacy_cbom_has_unknown_input_coverage():
    assert dashboard.summarize_scan_coverage(dashboard._scan_outcomes({"components": []}))["status"] == "Unknown"


def test_fallback_success_still_has_partial_discovery_coverage():
    coverage = dashboard.summarize_scan_coverage([
        {"Status": "No detections", "Scanner": "FALLBACK heuristic"},
        {"Status": "Skipped", "Scanner": "none"},
    ])
    assert coverage["status"] == "Partial"
    assert coverage["limited_inputs"] == 1 and coverage["skipped_inputs"] == 1

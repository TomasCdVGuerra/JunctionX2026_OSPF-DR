"""Unit and integration tests for dashboard.py (QuantumTrace CBOM UI)."""

import json
from enum import Enum
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import dashboard
from dashboard import (
    CRITICAL_WEIGHT,
    DEFAULT_CBOM_PATH,
    MEDIUM_WEIGHT,
    RISK_COLORS,
    RISK_ORDER,
    _build_cbom_from_findings,
    _component_to_row,
    _extract_evidence,
    _extract_native_crypto_properties,
    _extract_properties,
    _extract_property,
    _extract_tool_info,
    _first_dict,
    _load_cbom_uncached,
    _normalise,
    _risk_css,
    _safe_text_columns,
    load_findings_dataframe,
    render_dashboard,
    scan_uploaded_files,
)


class MockEnum(Enum):
    SIGN = "SIGN_VERIFY"
    ENCRYPT = "ENCRYPT_DECRYPT"


class MockUploadedFile:
    """Mock for Streamlit UploadedFile."""

    def __init__(self, name: str, content: bytes | str):
        self.name = name
        self.content = content.encode("utf-8") if isinstance(content, str) else content

    def getvalue(self) -> bytes:
        return self.content


# --- Unit Tests for Normalization & Extraction Helpers ---

def test_normalise_values():
    assert _normalise(None) == "unknown"
    assert _normalise(None, default="N/A") == "N/A"
    assert _normalise(True) == "true"
    assert _normalise(False) == "false"
    assert _normalise(MockEnum.SIGN) == "SIGN_VERIFY"
    assert _normalise("  RSA-2048  ") == "RSA-2048"
    assert _normalise("") == "unknown"
    assert _normalise(2048) == "2048"


def test_first_dict():
    assert _first_dict({"key": "val"}) == {"key": "val"}
    assert _first_dict([{"a": 1}, {"b": 2}]) == {"a": 1}
    assert _first_dict(["not a dict", {"b": 2}]) == {"b": 2}
    assert _first_dict("not a dict or list") == {}
    assert _first_dict([]) == {}


def test_extract_property():
    props = [
        {"name": "cryptotrace:riskRating", "value": "Critical"},
        {"name": "cryptotrace:quantumVulnerable", "value": True},
    ]
    assert _extract_property(props, "cryptotrace:riskRating") == "Critical"
    assert _extract_property(props, "cryptotrace:quantumVulnerable") == "true"
    assert _extract_property(props, "nonexistent") == "unknown"
    assert _extract_property(None, "any") == "unknown"
    assert _extract_property([{"invalid": "no name"}], "any") == "unknown"


def test_extract_properties_dict():
    props = [
        {"name": "alpha", "value": "1"},
        {"name": "beta", "value": False},
        {"invalid": "no_name"},
    ]
    result = _extract_properties(props)
    assert result == {"alpha": "1", "beta": "false"}
    assert _extract_properties("not_a_list") == {}


def test_extract_native_crypto_properties():
    comp = {
        "cryptoProperties": {
            "assetType": "algorithm",
            "oid": "1.2.840.113549.1.1.1",
            "algorithmProperties": {
                "primitive": "signature",
                "classicalSecurityLevel": 112,
                "nistQuantumSecurityLevel": 0,
            },
        }
    }
    native = _extract_native_crypto_properties(comp)
    assert native["assetType"] == "algorithm"
    assert native["oid"] == "1.2.840.113549.1.1.1"
    assert native["primitive"] == "signature"
    assert native["classicalSecurityLevel"] == "112"
    assert native["nistQuantumSecurityLevel"] == "0"


def test_extract_native_crypto_properties_empty():
    assert _extract_native_crypto_properties({}) == {}
    assert _extract_native_crypto_properties({"cryptoProperties": "not_a_dict"}) == {}


def test_extract_evidence_complete():
    comp = {
        "evidence": {
            "occurrences": [
                {
                    "location": "src/crypto.py",
                    "line": 42,
                    "matchedSnippet": "rsa.generate_private_key()",
                    "ruleId": "py-rsa-1024",
                    "nistStandard": "FIPS 186-4",
                }
            ]
        }
    }
    evidence = _extract_evidence(comp)
    assert evidence["Source Path"] == "src/crypto.py"
    assert evidence["Line Number"] == "42"
    assert evidence["Matched Snippet"] == "rsa.generate_private_key()"
    assert evidence["Rule ID"] == "py-rsa-1024"
    assert evidence["NIST Standard"] == "FIPS 186-4"


def test_extract_evidence_line_zero():
    """Ensure line 0 is preserved and not masked as unknown."""
    comp = {
        "evidence": {
            "occurrences": [
                {
                    "line": 0,
                    "location": {"line": 0},
                }
            ]
        }
    }
    evidence = _extract_evidence(comp)
    assert evidence["Line Number"] == "0"


def test_extract_evidence_fallbacks():
    comp = {
        "evidence": {
            "occurrences": [
                {
                    "location": {"line": 15, "snippet": "AES.new()"},
                    "source": {"filePath": "app/cipher.py", "ruleId": "RULE-1"},
                }
            ]
        }
    }
    evidence = _extract_evidence(comp)
    assert evidence["Source Path"] == "app/cipher.py"
    assert evidence["Line Number"] == "15"
    assert evidence["Matched Snippet"] == "AES.new()"
    assert evidence["Rule ID"] == "RULE-1"


def test_extract_tool_info_list_style():
    cbom = {
        "metadata": {
            "tools": [{"name": "OSPF-DR QuantumTrace", "version": "1.0.0"}]
        }
    }
    name, ver = _extract_tool_info(cbom)
    assert name == "OSPF-DR QuantumTrace"
    assert ver == "1.0.0"


def test_extract_tool_info_object_style():
    cbom = {
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CycloneDX CLI",
                        "version": "2.4.1",
                    }
                ]
            }
        }
    }
    name, ver = _extract_tool_info(cbom)
    assert name == "CycloneDX CLI"
    assert ver == "2.4.1"


def test_extract_tool_info_fallback():
    assert _extract_tool_info({}) == ("Unknown Scanner", "0.0")
    assert _extract_tool_info({"metadata": {"tools": []}}) == ("Unknown Scanner", "0.0")


# --- DataFrame Building & Row Conversion ---

def test_component_to_row():
    comp = {
        "name": "RSA-2048",
        "description": "RSA signature",
        "bom-ref": "crypto:1234",
        "properties": [
            {"name": "cryptotrace:riskRating", "value": "critical"},
            {"name": "cryptotrace:quantumVulnerable", "value": True},
            {"name": "cryptotrace:quantumSafe", "value": False},
            {"name": "cryptotrace:sourceType", "value": "cloud-posture"},
            {"name": "cryptotrace:sourcePath", "value": "cloud.json"},
            {"name": "cryptotrace:operation", "value": "SIGN_VERIFY"},
        ],
        "cryptoProperties": {
            "assetType": "algorithm",
            "oid": "1.2.840.113549.1.1.1",
        },
    }
    row = _component_to_row(comp)
    assert row["Algorithm"] == "RSA-2048"
    assert row["Risk Rating"] == "Critical"
    assert row["Quantum Vulnerable"] == "true"
    assert row["Quantum Safe"] == "false"
    assert row["Source Type"] == "cloud-posture"
    assert row["Source Path"] == "cloud.json"
    assert row["Operation"] == "SIGN_VERIFY"
    assert row["Crypto: assetType"] == "algorithm"
    assert row["Crypto: oid"] == "1.2.840.113549.1.1.1"


def test_load_findings_dataframe_empty():
    df = load_findings_dataframe({"components": []})
    assert len(df) == 0
    assert "Algorithm" in df.columns
    assert "Risk Rating" in df.columns
    assert "Source Path" in df.columns


def test_load_findings_dataframe_from_fixture():
    sample_cbom = {
        "components": [
            {
                "name": "AES-256-GCM",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Safe"},
                    {"name": "cryptotrace:sourceType", "value": "source-code"},
                    {"name": "cryptotrace:sourcePath", "value": "secure.py"},
                ],
            },
            {
                "name": "RSA-2048",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Critical"},
                    {"name": "cryptotrace:sourceType", "value": "cloud-posture"},
                    {"name": "cryptotrace:sourcePath", "value": "kms.json"},
                ],
            },
        ]
    }
    df = load_findings_dataframe(sample_cbom)
    assert len(df) == 2
    assert list(df["Algorithm"]) == ["AES-256-GCM", "RSA-2048"]
    assert list(df["Risk Rating"]) == ["Safe", "Critical"]


def test_safe_text_columns():
    df = load_findings_dataframe({"components": []})
    df_safe = _safe_text_columns(df)
    for col in ("Algorithm", "Source Path", "Matched Snippet", "Rule ID"):
        assert col in df_safe.columns


def test_risk_css():
    assert "dc2626" in _risk_css("Critical")
    assert "f59e0b" in _risk_css("Medium")
    assert "16a34a" in _risk_css("Safe")
    assert "6b7280" in _risk_css("Unknown")


# --- File Loading & Uncached Helpers ---

def test_load_cbom_uncached_from_bytes():
    payload = json.dumps({"test": "value"}).encode("utf-8")
    loaded = _load_cbom_uncached(file_bytes=payload)
    assert loaded == {"test": "value"}


def test_load_cbom_uncached_from_file(tmp_path):
    temp_cbom = tmp_path / "cbom_test.json"
    temp_cbom.write_text('{"components": []}', encoding="utf-8")
    loaded = _load_cbom_uncached(filepath=str(temp_cbom))
    assert loaded == {"components": []}


# --- UI and Dashboard Rendering Tests ---

def test_dashboard_renders_with_mock_st():
    """Verify render_dashboard executes cleanly with mocked Streamlit calls."""
    sample_cbom = {
        "metadata": {
            "timestamp": "2026-10-10T16:00:00Z",
            "tools": [{"name": "Test Scanner", "version": "1.0"}],
        },
        "components": [
            {
                "name": "RSA-1024",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Critical"},
                    {"name": "cryptotrace:sourceType", "value": "source-code"},
                    {"name": "cryptotrace:sourcePath", "value": "main.py"},
                ],
            }
        ],
    }

    with patch("dashboard.st") as mock_st:
        mock_st.file_uploader.return_value = None
        mock_st.multiselect.side_effect = lambda label, options, default: default
        mock_st.text_input.return_value = ""
        mock_st.button.return_value = False
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        render_dashboard(sample_cbom, cbom_path="test_cbom.json")

        mock_st.title.assert_called_with("QuantumTrace Cryptographic Risk Dashboard")
        mock_st.dataframe.assert_called()


def test_main_startup_without_cbom(tmp_path):
    """Verify main() starts up cleanly in empty state when cbom.json does not exist."""
    with patch("dashboard.DEFAULT_CBOM_PATH", tmp_path / "nonexistent.json"):
        with patch("dashboard.st") as mock_st:
            mock_st.session_state = {}
            mock_st.file_uploader.return_value = None
            mock_st.button.return_value = False
            dashboard.main()
            mock_st.set_page_config.assert_called_once()
            mock_st.info.assert_called_once()


def test_scan_uploaded_files_python():
    """Verify multiple Python files can be uploaded, scanned, and original paths preserved."""
    files = [
        MockUploadedFile("auth.py", "import hashlib\ndef h(p): return hashlib.md5(p)"),
        MockUploadedFile("crypto_keys.py", "from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)"),
    ]
    cbom, warnings = scan_uploaded_files(files)
    assert cbom is not None
    assert "components" in cbom
    assert len(cbom["components"]) >= 2
    paths = [
        next((p["value"] for p in c.get("properties", []) if p["name"] == "cryptotrace:sourcePath"), "")
        for c in cbom["components"]
    ]
    assert "auth.py" in paths
    assert "crypto_keys.py" in paths


def test_scan_uploaded_files_mixed_routing():
    """Verify mixed uploads (Python, Java, Go, JSON) route to appropriate scanners."""
    files = [
        MockUploadedFile("service.py", "import hashlib\nhashlib.sha1(b'x')"),
        MockUploadedFile("Receipt.java", "KeyPairGenerator.getInstance(\"RSA\");"),
        MockUploadedFile("main.go", "package main\nimport \"crypto/md5\"\nfunc f() { md5.New() }"),
        MockUploadedFile("kms.json", json.dumps({"Keys": [{"KeySpec": "RSA_2048", "KeyArn": "arn:123"}]})),
    ]
    cbom, warnings = scan_uploaded_files(files)
    assert cbom is not None
    assert len(cbom["components"]) >= 4
    source_types = {
        next((p["value"] for p in c.get("properties", []) if p["name"] == "cryptotrace:sourceType"), "")
        for c in cbom["components"]
    }
    assert "source-code" in source_types
    assert "cloud-posture" in source_types


def test_scan_uploaded_files_malformed_resilience():
    """Verify a malformed upload does not crash scanning of other valid files."""
    files = [
        MockUploadedFile("invalid.xyz", "unsupported binary data"),
        MockUploadedFile("valid.py", "import hashlib\nhashlib.md5(b'123')"),
    ]
    cbom, warnings = scan_uploaded_files(files)
    assert cbom is not None
    assert len(cbom["components"]) >= 1
    assert any("invalid.xyz" in w for w in warnings)


def test_scan_uploaded_files_empty():
    """Verify scanning with empty uploads list returns warning."""
    cbom, warnings = scan_uploaded_files([])
    assert cbom is None
    assert len(warnings) > 0


def test_cbom_generation_in_memory():
    """Verify CBOM JSON structure is generated in memory after scanning."""
    findings = [
        {
            "canonical_algorithm": "RSA-2048",
            "risk_rating": "Critical",
            "source_type": "source-code",
            "source_path": "main.py",
            "operation": "KEYGEN",
        }
    ]
    cbom = _build_cbom_from_findings(findings)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 1


def test_search_with_regex_metacharacters():
    """Verify literal search safely handles regex special characters without error."""
    sample_cbom = {
        "components": [
            {
                "name": "RSA (2048)",
                "description": "Legacy public key + [padding] * 2",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Critical"},
                    {"name": "cryptotrace:sourceType", "value": "source-code"},
                    {"name": "cryptotrace:sourcePath", "value": "path/file.py"},
                ],
            }
        ]
    }
    df = _safe_text_columns(load_findings_dataframe(sample_cbom))

    # Test problematic regex metacharacters
    for test_query in ("RSA (2048)", "[", "+", "*", "SHA-1", "\\"):
        query = test_query.casefold()
        mask = (
            df["Algorithm"].str.casefold().str.contains(query, regex=False, na=False)
            | df["Description"].str.casefold().str.contains(query, regex=False, na=False)
        )
        filtered = df[mask]
        assert isinstance(filtered, object)


def test_pydantic_crypto_finding_integration_with_cbom_and_dashboard():
    """Verify that canonical Pydantic CryptoFinding objects integrate with CBOM and dashboard."""
    from scanner.models import AssetType, CryptoFinding, Evidence, QuantumRiskLevel

    finding = CryptoFinding(
        algorithm_name="RSA-2048",
        source_type="cloud-posture",
        key_size=2048,
        observation="configured",
        asset_type=AssetType.KEY,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        evidence=[
            Evidence(file_path="kms_key_inventory.json", rule_id="AWS-KMS-RSA", line_number=12)
        ],
    )

    cbom = _build_cbom_from_findings([finding])
    assert cbom["bomFormat"] == "CycloneDX"
    assert len(cbom["components"]) == 1

    df = load_findings_dataframe(cbom)
    assert len(df) == 1
    assert df.iloc[0]["Algorithm"] == "RSA-2048"
    assert df.iloc[0]["Risk Rating"] == "Critical"
    assert df.iloc[0]["Source Type"] == "cloud-posture"


def test_real_scanner_used_when_scan_method_exists_bundled_data(monkeypatch):
    """Test fails if a real scanner module exists with a scan method but the fallback was still used."""
    mock_findings = [
        {
            "canonical_algorithm": "RSA-4096",
            "risk_rating": "Critical",
            "source_type": "source-code",
            "source_path": "crypto_service.py",
            "operation": "KEYGEN",
        }
    ]
    mock_scan_dir = MagicMock(return_value=mock_findings)

    # Provide real scanner module with scan method
    monkeypatch.setattr(dashboard.source_scanner, "scan_source_directory", mock_scan_dir, raising=False)

    # Spy on the fallback function to verify it is NOT used
    mock_fallback = MagicMock(wraps=dashboard._scan_source_file_fallback)
    monkeypatch.setattr(dashboard, "_scan_source_file_fallback", mock_fallback)

    cbom, warnings = dashboard.scan_bundled_data()

    # The real scanner method MUST be invoked
    assert mock_scan_dir.called, "Real scanner module scan method was not invoked!"

    # The fallback MUST NOT be used when real scanner exists with a scan method
    assert not mock_fallback.called, "Fallback heuristic was used even though real scanner module had a scan method!"

    # Every finding from that scanner must carry the real module tag, NOT fallback
    df = dashboard.load_findings_dataframe(cbom)
    src_rows = df[df["Source Type"] == "source-code"]
    assert len(src_rows) > 0
    assert (src_rows["Scanner source"] == f"real: {dashboard.source_scanner.__name__}").all()
    assert not (src_rows["Scanner source"] == "FALLBACK heuristic").any()


def test_real_scanner_used_when_scan_method_exists_uploaded_files(monkeypatch):
    """Test fails if scan_uploaded_files uses fallback when a real file scanner exists."""
    mock_findings = [
        {
            "canonical_algorithm": "Ed25519",
            "risk_rating": "Critical",
            "source_type": "source-code",
            "source_path": "uploaded.py",
            "operation": "SIGN",
        }
    ]
    mock_scan_file = MagicMock(return_value=mock_findings)

    monkeypatch.setattr(dashboard.source_scanner, "scan_file", mock_scan_file, raising=False)

    mock_fallback = MagicMock(wraps=dashboard._scan_source_file_fallback)
    monkeypatch.setattr(dashboard, "_scan_source_file_fallback", mock_fallback)

    uploaded = MockUploadedFile("uploaded.py", "import ed25519")
    cbom, warnings = dashboard.scan_uploaded_files([uploaded])

    assert mock_scan_file.called, "Real scan_file method was not called!"
    assert not mock_fallback.called, "Fallback heuristic was called despite real scanner existing!"

    df = dashboard.load_findings_dataframe(cbom)
    assert (df["Scanner source"] == f"real: {dashboard.source_scanner.__name__}").all()
    assert not (df["Scanner source"] == "FALLBACK heuristic").any()


def test_fallback_warning_banner_shown_when_fallback_used():
    """Verify render_dashboard displays st.warning banner listing input types when fallback is used."""
    cbom = {
        "components": [
            {
                "name": "RSA-2048",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Critical"},
                    {"name": "cryptotrace:sourceType", "value": "source-code"},
                    {"name": "cryptotrace:scannerSource", "value": "FALLBACK heuristic"},
                ],
            },
            {
                "name": "AES-128",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Medium"},
                    {"name": "cryptotrace:sourceType", "value": "cloud-posture"},
                    {"name": "cryptotrace:scannerSource", "value": "FALLBACK heuristic"},
                ],
            },
        ]
    }
    with patch("dashboard.st") as mock_st:
        mock_st.file_uploader.return_value = None
        mock_st.multiselect.side_effect = lambda label, options, default: default
        mock_st.text_input.return_value = ""
        mock_st.button.return_value = False
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        render_dashboard(cbom)

        warning_calls = [str(call.args[0]) for call in mock_st.warning.call_args_list if call.args]
        fallback_warnings = [msg for msg in warning_calls if "Fallback heuristic" in msg]
        assert len(fallback_warnings) == 1
        assert "cloud-posture" in fallback_warnings[0]
        assert "source-code" in fallback_warnings[0]


def test_fallback_warning_banner_not_shown_when_all_real_scanners():
    """Verify render_dashboard does NOT display fallback banner when only real scanners were used."""
    cbom = {
        "components": [
            {
                "name": "RSA-2048",
                "properties": [
                    {"name": "cryptotrace:riskRating", "value": "Critical"},
                    {"name": "cryptotrace:sourceType", "value": "source-code"},
                    {"name": "cryptotrace:scannerSource", "value": "real: scanner.source_scanner"},
                ],
            }
        ]
    }
    with patch("dashboard.st") as mock_st:
        mock_st.file_uploader.return_value = None
        mock_st.multiselect.side_effect = lambda label, options, default: default
        mock_st.text_input.return_value = ""
        mock_st.button.return_value = False
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        render_dashboard(cbom)

        warning_calls = [str(call.args[0]) for call in mock_st.warning.call_args_list if call.args]
        fallback_warnings = [msg for msg in warning_calls if "Fallback heuristic" in msg]
        assert len(fallback_warnings) == 0


def test_scanner_choice_logging(caplog):
    """Verify scanner choice (real vs fallback) is logged via logger.info."""
    import logging
    with caplog.at_level(logging.INFO):
        dashboard.scan_bundled_data()
    assert any("FALLBACK heuristic" in record.message or "Using real scanner" in record.message for record in caplog.records)


# --- Petty Dashboard Tests ---

def test_load_findings_dataframe_malformed_components_resilience():
    """Petty: Verify load_findings_dataframe never crashes on invalid CBOM structures and preserves schema."""
    expected_cols = [
        "Algorithm", "Risk Rating", "Scanner source", "Source Type", "Source Path",
        "Operation", "Quantum Vulnerable", "Quantum Safe", "Line Number",
        "Matched Snippet", "Rule ID", "NIST Standard", "BOM Reference", "Description",
    ]

    for bad_cbom in (
        {},
        {"components": None},
        {"components": "string_not_list"},
        {"components": 12345},
        {"components": [{}]},
        {"components": [{"invalid_key": "junk"}]},
    ):
        df = load_findings_dataframe(bad_cbom)
        for col in expected_cols:
            assert col in df.columns, f"Missing standard column {col} for malformed CBOM input {bad_cbom}!"


def test_load_findings_dataframe_direct_crypto_finding_list():
    """Petty: Verify load_findings_dataframe directly accepts a list of CryptoFinding models."""
    from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel

    f = CryptoFinding(
        algorithm_name="Ed25519",
        asset_type=AssetType.ALGORITHM,
        source_type="source-code",
        crypto_function=CryptoFunction.SIGN,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        observation="observed",
        evidence=[Evidence(file_path="auth/token.go", rule_id="GO-ED25519", line_number=77)],
    )

    df = load_findings_dataframe([f])
    assert len(df) == 1
    assert df.iloc[0]["Algorithm"] == "Ed25519"
    assert df.iloc[0]["Risk Rating"] == "Critical"
    assert df.iloc[0]["Source Path"] == "auth/token.go"
    assert df.iloc[0]["Line Number"] == "77"
    assert df.iloc[0]["Rule ID"] == "GO-ED25519"


def test_risk_css_exhaustive_tiers_and_fallbacks():
    """Petty: Verify _risk_css produces valid CSS styling for all standard and non-standard risk labels."""
    assert "dc2626" in _risk_css("Critical")
    assert "f59e0b" in _risk_css("Medium")
    assert "16a34a" in _risk_css("Safe")
    assert "6b7280" in _risk_css("Unknown")
    assert "6b7280" in _risk_css("completely_invented_risk_tier")
    assert "6b7280" in _risk_css("")
    assert "6b7280" in _risk_css(None)


def test_safe_text_columns_mixed_types_and_nans():
    """Petty: Verify _safe_text_columns normalizes NaNs, booleans, and numbers in text columns into safe strings."""
    import pandas as pd
    import numpy as np

    raw_df = pd.DataFrame([
        {"Algorithm": "AES", "Source Path": np.nan, "Matched Snippet": 42, "Rule ID": True},
        {"Algorithm": None, "Source Path": "test.go", "Matched Snippet": None, "Rule ID": False},
    ])

    clean_df = _safe_text_columns(raw_df)
    assert clean_df.iloc[0]["Algorithm"] == "AES"
    assert clean_df.iloc[0]["Source Path"] == "unknown"
    assert "42" in clean_df.iloc[0]["Matched Snippet"]
    assert clean_df.iloc[0]["Rule ID"] == "True"
    assert clean_df.iloc[1]["Algorithm"] == "unknown"
    assert clean_df.iloc[1]["Source Path"] == "test.go"
    assert clean_df.iloc[1]["Matched Snippet"] == "unknown"
    assert clean_df.iloc[1]["Rule ID"] == "False"


def test_extract_evidence_deep_fallback_hierarchy():
    """Petty: Verify _extract_evidence drills down into all fallback CycloneDX evidence locations."""
    # 1. Location string
    comp1 = {
        "evidence": {
            "occurrences": [
                {"location": "simple/file/path.go", "line": 15, "ruleId": "RULE-1"}
            ]
        }
    }
    ev1 = _extract_evidence(comp1)
    assert ev1["Source Path"] == "simple/file/path.go"
    assert ev1["Line Number"] == "15"
    assert ev1["Rule ID"] == "RULE-1"

    # 2. Source nested dict
    comp2 = {
        "evidence": {
            "occurrences": [
                {
                    "source": {"filePath": "nested/path.py", "ruleId": "RULE-PY", "nistStandard": "FIPS 197"},
                    "lineNumber": 99,
                }
            ]
        }
    }
    ev2 = _extract_evidence(comp2)
    assert ev2["Source Path"] == "nested/path.py"
    assert ev2["Line Number"] == "99"
    assert ev2["Rule ID"] == "RULE-PY"
    assert ev2["NIST Standard"] == "FIPS 197"


def test_pcap_fallback_empty_and_tls_detection(tmp_path):
    """Regression: Empty/DNS-only PCAP yields 0 findings; TLS marker yields finding with valid evidence packet_number."""
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(b"")
    assert dashboard._scan_pcap_file_fallback(empty_pcap) == []

    dns_pcap = tmp_path / "dns.pcap"
    dns_pcap.write_bytes(b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00")
    assert dashboard._scan_pcap_file_fallback(dns_pcap) == []

    tls_pcap = tmp_path / "tls.pcap"
    tls_pcap.write_bytes(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03")
    tls_findings = dashboard._scan_pcap_file_fallback(tls_pcap)
    assert len(tls_findings) == 1
    assert tls_findings[0]["canonical_algorithm"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert tls_findings[0]["line_number"] is None
    assert tls_findings[0]["packet_number"] == 1


def test_cloud_fallback_preserves_exact_keyspecs(tmp_path):
    """Regression: Cloud fallback preserves RSA-3072, ECC-NIST-P384 without defaulting to RSA-2048."""
    cloud_json = tmp_path / "kms.json"
    cloud_json.write_text(json.dumps({
        "Keys": [
            {"KeySpec": "RSA_3072", "KeyArn": "arn:aws:kms:1:key/rsa3072"},
            {"KeySpec": "ECC_NIST_P384", "KeyArn": "arn:aws:kms:1:key/ecc384"},
            {"KeySpec": "SYMMETRIC_DEFAULT", "KeyArn": "arn:aws:kms:1:key/symm"},
        ]
    }))
    findings = dashboard._scan_cloud_file_fallback(cloud_json)
    algos = {f["canonical_algorithm"] for f in findings}
    assert "RSA-3072" in algos
    assert "ECC-NIST-P384" in algos
    assert "AES-256-GCM" in algos
    assert "RSA-2048" not in algos


def test_source_fallback_ignores_comments(tmp_path):
    """Regression: Source fallback ignores comments containing crypto names."""
    py_file = tmp_path / "clean.py"
    py_file.write_text("""
# We decided that md5 and sha1 are completely forbidden here
// Also do not use deriveKey for passwords
def process(data):
    return data
""")
    findings = dashboard._scan_source_file_fallback(py_file)
    assert len(findings) == 0



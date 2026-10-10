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

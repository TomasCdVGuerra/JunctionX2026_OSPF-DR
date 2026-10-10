"""Exhaustive unit tests for the CycloneDX 1.6 CBOM Serializer."""

import json
import os
from datetime import datetime
from enum import Enum
from pathlib import Path

import jsonschema
import pytest

from scanner.cbom import CBOMSerializer

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "bom-1.6.schema.json"


@pytest.fixture(scope="session")
def cyclonedx_schema():
    """Load local CycloneDX 1.6 schema for offline validation."""
    if not SCHEMA_PATH.exists():
        pytest.skip(f"CycloneDX schema not found at {SCHEMA_PATH}")
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class MockEnum(Enum):
    SIGN = "SIGN_VERIFY"
    ENCRYPT = "ENCRYPT_DECRYPT"


class MockFindingObject:
    def __init__(self):
        self.canonical_algorithm = "ECC-NIST-P256"
        self.risk_rating = "Medium"
        self.operation = MockEnum.SIGN


def test_cbom_root_metadata():
    """Verify baseline CycloneDX metadata initialization."""
    serializer = CBOMSerializer(scanner_name="Test Scanner", version="9.9.9")
    doc = serializer.document

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["version"] == 1
    assert "urn:uuid:" in doc["serialNumber"]
    assert doc["metadata"]["tools"][0]["name"] == "Test Scanner"


def test_add_finding_dictionary():
    """Verify dictionary finding populates properties correctly."""
    serializer = CBOMSerializer()
    serializer.add_finding({
        "canonical_algorithm": "RSA-2048",
        "explanation": "Test explanation",
        "risk_rating": "Critical",
        "quantum_vulnerable": True,
        "source_type": "cloud-posture",
        "source_path": "mock/path.json",
        "operation": "SIGN_VERIFY",
    })

    comp = serializer.document["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}

    assert comp["name"] == "RSA-2048"
    assert props["cryptotrace:riskRating"] == "Critical"
    assert props["cryptotrace:quantumVulnerable"] == "true"
    assert props["cryptotrace:quantumSafe"] == "false"


def test_missing_values_become_unknown():
    """Verify missing or None attributes gracefully degrade to 'unknown'."""
    serializer = CBOMSerializer()
    serializer.add_finding({"canonical_algorithm": None})

    props = {p["name"]: p["value"] for p in serializer.document["components"][0]["properties"]}

    assert serializer.document["components"][0]["name"] == "unknown"
    assert props["cryptotrace:riskRating"] == "unknown"
    assert props["cryptotrace:sourceType"] == "unknown"


def test_enum_and_object_unwrapping():
    """Verify object attributes and Enums are extracted and unwrapped."""
    serializer = CBOMSerializer()
    serializer.add_finding(MockFindingObject())

    comp = serializer.document["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}

    assert comp["name"] == "ECC-NIST-P256"
    assert props["cryptotrace:riskRating"] == "Medium"
    assert props["cryptotrace:operation"] == "SIGN_VERIFY"


def test_deterministic_bom_ref():
    """Verify identical findings produce the exact same bom-ref hash."""
    serializer1, serializer2 = CBOMSerializer(), CBOMSerializer()
    finding = {"canonical_algorithm": "AES-256", "source_path": "main.py"}

    serializer1.add_finding(finding)
    serializer2.add_finding(finding)

    assert serializer1.document["components"][0]["bom-ref"] == serializer2.document["components"][0]["bom-ref"]


def test_to_json_file_output(tmp_path):
    """Verify JSON string generation and file writing."""
    filepath = tmp_path / "test_cbom.json"
    serializer = CBOMSerializer()
    serializer.add_finding({"canonical_algorithm": "AES"})

    json_str = serializer.to_json(filepath=str(filepath))

    assert "AES" in json_str
    assert os.path.exists(filepath)
    with open(filepath, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded["components"][0]["name"] == "AES"


def test_cbom_validates_against_cyclonedx_1_6_schema(cyclonedx_schema):
    """Validate generated CBOM against official CycloneDX 1.6 JSON schema."""
    serializer = CBOMSerializer()
    serializer.add_finding({
        "canonical_algorithm": "RSA-2048",
        "explanation": "Test explanation",
        "risk_rating": "Critical",
        "quantum_vulnerable": True,
        "source_type": "cloud-posture",
        "source_path": "cloud-posture/kms.json",
        "operation": "SIGN_VERIFY",
    })
    serializer.add_finding({
        "canonical_algorithm": "AES-256-GCM",
        "explanation": "Symmetric cipher",
        "risk_rating": "Safe",
        "quantum_safe": True,
        "source_type": "source-code",
        "source_path": "sample.py",
        "operation": "ENCRYPT_DECRYPT",
    })

    # Validate against schema
    jsonschema.validate(instance=serializer.document, schema=cyclonedx_schema)


def test_empty_components_validates_schema(cyclonedx_schema):
    """Verify an empty scan with zero findings is still a valid CycloneDX document."""
    serializer = CBOMSerializer()
    assert serializer.document["components"] == []
    jsonschema.validate(instance=serializer.document, schema=cyclonedx_schema)


def test_timestamp_is_valid_iso8601():
    """Verify timestamp adheres strictly to ISO-8601 UTC format with trailing Z."""
    serializer = CBOMSerializer()
    ts = serializer.document["metadata"]["timestamp"]
    assert ts.endswith("Z")
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed is not None


def test_tool_name_deduplication():
    """Verify tool name suffixing logic does not duplicate 'Scanner'."""
    s1 = CBOMSerializer(scanner_name="Custom Tool")
    assert s1.document["metadata"]["tools"][0]["name"] == "Custom Tool Scanner"

    s2 = CBOMSerializer(scanner_name="Custom Tool Scanner")
    assert s2.document["metadata"]["tools"][0]["name"] == "Custom Tool Scanner"


def test_multiple_findings_distinct_bom_refs():
    """Verify distinct findings get distinct bom-ref values and all append."""
    serializer = CBOMSerializer()
    serializer.add_finding({"canonical_algorithm": "RSA-2048", "source_path": "a.py", "operation": "sign"})
    serializer.add_finding({"canonical_algorithm": "AES-256", "source_path": "b.py", "operation": "encrypt"})

    assert len(serializer.document["components"]) == 2
    ref1 = serializer.document["components"][0]["bom-ref"]
    ref2 = serializer.document["components"][1]["bom-ref"]
    assert ref1 != ref2


def test_unicode_and_special_characters():
    """Verify Unicode strings and special characters in paths and descriptions."""
    serializer = CBOMSerializer()
    serializer.add_finding({
        "canonical_algorithm": "AES-256",
        "explanation": "Operação criptográfica com acentuação e cedilha: migração PQC",
        "source_path": "caminho/com espaços/ficheiro.py",
    })

    json_str = serializer.to_json()
    assert "migração PQC" in json_str
    parsed = json.loads(json_str)
    assert parsed["components"][0]["description"] == "Operação criptográfica com acentuação e cedilha: migração PQC"


# --- Petty CBOM Tests ---

def test_cbom_pydantic_crypto_finding_serialization_and_schema_validation(cyclonedx_schema):
    """Petty: Verify actual Pydantic CryptoFinding objects across all risk levels validate against CycloneDX 1.6 schema."""
    from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel

    findings = [
        CryptoFinding(
            algorithm_name="RSA-2048",
            asset_type=AssetType.KEY,
            source_type="cloud-posture",
            key_size=2048,
            crypto_function=CryptoFunction.KEYGEN,
            quantum_risk=QuantumRiskLevel.CRITICAL,
            observation="configured",
            evidence=[Evidence(file_path="cloud/kms.json", rule_id="AWS-KMS-01", line_number=10)],
        ),
        CryptoFinding(
            algorithm_name="AES-128-GCM",
            asset_type=AssetType.ALGORITHM,
            source_type="source-code",
            key_size=128,
            mode="GCM",
            crypto_function=CryptoFunction.ENCRYPT,
            quantum_risk=QuantumRiskLevel.MEDIUM,
            observation="observed",
            evidence=[Evidence(file_path="src/cipher.go", rule_id="GO-AES-128", line_number=42)],
        ),
        CryptoFinding(
            algorithm_name="HMAC-SHA256",
            asset_type=AssetType.ALGORITHM,
            source_type="source-code",
            crypto_function=CryptoFunction.MAC,
            quantum_risk=QuantumRiskLevel.SAFE,
            observation="observed",
            evidence=[Evidence(file_path="src/auth.go", rule_id="GO-HMAC", line_number=100)],
        ),
    ]

    serializer = CBOMSerializer()
    for f in findings:
        serializer.add_finding(f)

    # Must strictly validate against official CycloneDX 1.6 schema
    jsonschema.validate(instance=serializer.document, schema=cyclonedx_schema)

    # Check component values
    assert len(serializer.document["components"]) == 3
    c0 = serializer.document["components"][0]
    p0 = {p["name"]: p["value"] for p in c0["properties"]}
    assert p0["cryptotrace:sourcePath"] == "cloud/kms.json"
    assert p0["cryptotrace:riskRating"] == "critical"
    assert p0["cryptotrace:quantumVulnerable"] == "true"


def test_cbom_evidence_array_source_path_extraction():
    """Petty: Verify source_path is strictly extracted from finding.evidence[0].file_path."""
    from scanner.models import AssetType, CryptoFinding, Evidence, QuantumRiskLevel

    ev1 = Evidence(file_path="first/path.go", rule_id="R1", line_number=1)
    ev2 = Evidence(file_path="second/path.go", rule_id="R2", line_number=2)
    finding = CryptoFinding(
        algorithm_name="Ed25519",
        source_type="source-code",
        observation="observed",
        quantum_risk=QuantumRiskLevel.CRITICAL,
        evidence=[ev1, ev2],
    )

    serializer = CBOMSerializer()
    serializer.add_finding(finding)

    comp = serializer.document["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cryptotrace:sourcePath"] == "first/path.go"


def test_cbom_empty_evidence_array_graceful_degradation():
    """Petty: Verify finding with empty evidence list gracefully degrades to 'unknown' without raising IndexError."""
    serializer = CBOMSerializer()
    serializer.add_finding({
        "canonical_algorithm": "SHA-256",
        "evidence": [],
    })

    comp = serializer.document["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cryptotrace:sourcePath"] == "unknown"


def test_cbom_bom_ref_sensitivity_to_operation_and_source_type():
    """Petty: Verify bom-ref hash differentiates findings differing only by operation or source_type."""
    s = CBOMSerializer()
    base = {"canonical_algorithm": "RSA-2048", "source_path": "main.py"}

    f1 = {**base, "source_type": "source-code", "operation": "SIGN"}
    f2 = {**base, "source_type": "source-code", "operation": "VERIFY"}
    f3 = {**base, "source_type": "cloud-posture", "operation": "SIGN"}

    s.add_finding(f1)
    s.add_finding(f2)
    s.add_finding(f3)

    refs = [c["bom-ref"] for c in s.document["components"]]
    assert len(refs) == 3
    assert len(set(refs)) == 3, "bom-ref hashes must be unique across differing operations or source_types!"


def test_cbom_arbitrary_object_missing_attributes_graceful():
    """Petty: Verify serializer handles an empty/arbitrary object with zero expected attributes without crashing."""
    class EmptyObj:
        pass

    serializer = CBOMSerializer()
    serializer.add_finding(EmptyObj())

    assert len(serializer.document["components"]) == 1
    comp = serializer.document["components"][0]
    assert comp["name"] == "unknown"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cryptotrace:riskRating"] == "unknown"
    assert props["cryptotrace:sourcePath"] == "unknown"


def test_cbom_boolean_properties_stringified_strictly_lowercase():
    """Petty: CycloneDX properties are strings; booleans must be strictly lowercase 'true' or 'false' (never 'True'/'False')."""
    serializer = CBOMSerializer()
    serializer.add_finding({
        "canonical_algorithm": "AES-256",
        "quantum_vulnerable": False,
        "quantum_safe": True,
    })

    comp = serializer.document["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cryptotrace:quantumVulnerable"] == "false"
    assert props["cryptotrace:quantumSafe"] == "true"
    assert props["cryptotrace:quantumVulnerable"] != "False"
    assert props["cryptotrace:quantumSafe"] != "True"


def test_cbom_bom_ref_unique_across_different_lines_and_duplicates():
    """Verify findings differing only by line number or identical duplicate occurrences get unique bom-ref IDs."""
    s = CBOMSerializer()
    f1 = {"canonical_algorithm": "AES-256", "source_path": "main.py", "operation": "encrypt", "line_number": 10}
    f2 = {"canonical_algorithm": "AES-256", "source_path": "main.py", "operation": "encrypt", "line_number": 50}
    f3 = {"canonical_algorithm": "AES-256", "source_path": "main.py", "operation": "encrypt", "line_number": 10}

    s.add_finding(f1)
    s.add_finding(f2)
    s.add_finding(f3)

    refs = [c["bom-ref"] for c in s.document["components"]]
    assert len(refs) == 3
    assert len(set(refs)) == 3, f"All bom-ref IDs in BOM document must be unique, got: {refs}"
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
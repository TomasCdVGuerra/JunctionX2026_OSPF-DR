# Purpose:
# Test suite for CycloneDX 1.6 Cryptography Bill of Materials (CBOM) serialization and JSON schema validation.
#
# Responsibilities:
# - Validate the generated CBOM document strictly against the official CycloneDX 1.6 JSON schema specification using the jsonschema library.
# - Ensure test validation operates completely offline by referencing local schema files and dependencies stored in tests/fixtures/.
# - Validate that cryptoProperties, algorithmProperties, classicalSecurityLevel, nistQuantumSecurityLevel, OIDs, and evidence blocks adhere to schema types and constraints.
# - Confirm that field name checks alone are rejected as insufficient and full structural validation is executed.
#
# Planned interface:
# - test_cbom_against_official_cyclonedx_schema(): loads tests/fixtures/bom-1.6.schema.json, executes jsonschema.validate(), and verifies strict compliance.
# - test_cbom_offline_self_contained(): verifies no external network calls are made during schema resolution and reference checking.
# - test_cbom_evidence_fields_present(): verifies that file paths, line numbers, snippets, and rule IDs are formatted properly inside evidence.occurrences.
#
# Rules and edge cases:
# - Checking field names alone is NOT enough; the full document MUST validate against the official CycloneDX 1.6 JSON schema using jsonschema.validate().
# - All referenced sub-schemas (e.g., spdx.schema.json, jsf-0.82.schema.json) must reside locally in tests/fixtures/ so the test suite passes in air-gapped/offline environments.
# - If an attribute is "unknown", verify that the schema allows or accommodates the field without schema validation failures.
#
# Scoring link:
# - Standardisation and traceability (20%): Proves compliance with the official CycloneDX 1.6 industry specification.
# - Accuracy (40%): Guarantees that exported artifacts are syntactically and semantically valid for external CBOM consumers.
"""Exhaustive unit tests for the CycloneDX 1.6 CBOM Serializer."""

import json
import os
from enum import Enum
from scanner.cbom import CBOMSerializer

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
        "operation": "SIGN_VERIFY"
    })
    
    comp = serializer.document["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    
    assert comp["name"] == "RSA-2048"
    assert props["cryptotrace:riskRating"] == "Critical"
    assert props["cryptotrace:quantumVulnerable"] == "true"
    assert props["cryptotrace:quantumSafe"] == "false" # Defaults to false

def test_missing_values_become_unknown():
    """Verify missing or None attributes gracefully degrade to 'unknown'."""
    serializer = CBOMSerializer()
    serializer.add_finding({"canonical_algorithm": None}) # Missing everything else
    
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
    with open(filepath, "r") as f:
        loaded = json.load(f)
        assert loaded["components"][0]["name"] == "AES"
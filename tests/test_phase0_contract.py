import json

import pytest
from pydantic import ValidationError

from scanner.models import AssetType, CryptoFinding, Evidence, QuantumRiskLevel


def sample_finding():
    return CryptoFinding(
        algorithm_name="RSA", source_type="cloud-posture", key_size=2048,
        observation="configured", asset_type=AssetType.KEY,
        evidence=[Evidence(file_path="kms_key_inventory.json", json_path="$.Keys[0]", rule_id="AWS-KMS-RSA")],
    )


def test_roundtrip():
    finding = sample_finding()
    assert CryptoFinding.model_validate(json.loads(finding.model_dump_json())) == finding
    assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN


def test_reject_invalid_source():
    with pytest.raises(ValidationError):
        CryptoFinding.model_validate({**sample_finding().to_dict(), "source_type": "bad"})


def test_invalid_key_size_and_missing_evidence():
    payload = sample_finding().to_dict()
    payload["key_size"] = -1
    with pytest.raises(ValidationError):
        CryptoFinding.model_validate(payload)
    payload["key_size"] = 2048
    payload["evidence"] = []
    with pytest.raises(ValidationError):
        CryptoFinding.model_validate(payload)


def test_unknown_attributes_not_guessed():
    finding = sample_finding()
    assert finding.mode is None and finding.oid is None
    assert "mode" not in finding.to_dict()


# --- Petty Contract Tests ---

def test_immutability_and_forbid_extra_fields():
    """Petty: Verify extra='forbid' prevents sneaking in unauthorized attributes."""
    payload = sample_finding().to_dict()
    payload["arbitrary_hack"] = "malicious"
    with pytest.raises(ValidationError):
        CryptoFinding.model_validate(payload)


def test_confidence_literal_enforcement():
    """Petty: Confidence must strictly be 'low', 'medium', or 'high'."""
    payload = sample_finding().to_dict()
    for valid in ("low", "medium", "high"):
        payload["confidence"] = valid
        f = CryptoFinding.model_validate(payload)
        assert f.confidence == valid

    for invalid in ("critical", "extreme", "none", "", 123):
        payload["confidence"] = invalid
        with pytest.raises(ValidationError):
            CryptoFinding.model_validate(payload)


def test_observation_literal_enforcement():
    """Petty: Observation must strictly be in ('declared', 'configured', 'advertised', 'negotiated', 'observed')."""
    payload = sample_finding().to_dict()
    for valid in ("declared", "configured", "advertised", "negotiated", "observed"):
        payload["observation"] = valid
        f = CryptoFinding.model_validate(payload)
        assert f.observation == valid

    for invalid in ("assumed", "guessed", "speculative", "inferred", ""):
        payload["observation"] = invalid
        with pytest.raises(ValidationError):
            CryptoFinding.model_validate(payload)


def test_algorithm_name_whitespace_stripped_and_non_empty():
    """Petty: Algorithm name must strip whitespace and reject pure whitespace."""
    payload = sample_finding().to_dict()
    payload["algorithm_name"] = "  AES-GCM-256  "
    f = CryptoFinding.model_validate(payload)
    assert f.algorithm_name == "AES-GCM-256"

    for invalid in ("", "   ", "\t\n"):
        payload["algorithm_name"] = invalid
        with pytest.raises(ValidationError):
            CryptoFinding.model_validate(payload)


def test_key_size_boundary_zero_rejected():
    """Petty: key_size must be gt=0; zero is strictly rejected."""
    payload = sample_finding().to_dict()
    payload["key_size"] = 0
    with pytest.raises(ValidationError):
        CryptoFinding.model_validate(payload)

    payload["key_size"] = 1
    f = CryptoFinding.model_validate(payload)
    assert f.key_size == 1


def test_evidence_contract_validation():
    """Petty: Evidence must reject line_number < 1, empty rule_id, empty file_path, or extra fields."""
    # line_number < 1
    with pytest.raises(ValidationError):
        Evidence(file_path="foo.go", rule_id="R1", line_number=0)
    with pytest.raises(ValidationError):
        Evidence(file_path="foo.go", rule_id="R1", line_number=-1)

    # packet_number < 1
    with pytest.raises(ValidationError):
        Evidence(file_path="foo.pcap", rule_id="R1", packet_number=0)

    # empty rule_id or file_path
    with pytest.raises(ValidationError):
        Evidence(file_path="", rule_id="R1")
    with pytest.raises(ValidationError):
        Evidence(file_path="foo.go", rule_id="")

    # extra fields on Evidence
    with pytest.raises(ValidationError):
        Evidence(file_path="foo.go", rule_id="R1", custom_tag="illegal")


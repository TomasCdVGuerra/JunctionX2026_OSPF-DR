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

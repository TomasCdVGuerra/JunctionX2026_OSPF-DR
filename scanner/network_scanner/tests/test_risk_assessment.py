"""Network risk policy and assessed findings, independent of protocol extraction."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.models import AssetType, CryptoFinding, CryptoFunction as F, Evidence, QuantumRiskLevel as Q
from scanner.network_scanner.analyser import risk_assessment as risk


@pytest.mark.parametrize("name,bits,mode,function,quantum,classical", [
    ("future-algorithm", None, None, F.UNKNOWN, Q.UNKNOWN, Q.UNKNOWN),
    ("fake-ML-KEM-768", None, None, F.KEY_EXCHANGE, Q.UNKNOWN, Q.UNKNOWN),
    ("AES", None, "GCM", F.ENCRYPT, Q.UNKNOWN, Q.UNKNOWN),
    ("AES", 64, "GCM", F.ENCRYPT, Q.UNKNOWN, Q.UNKNOWN),
    ("aes", 128, "GCM", F.ENCRYPT, Q.MEDIUM, Q.SAFE),
    ("AES", 192, "GCM", F.ENCRYPT, Q.MEDIUM, Q.SAFE),
    ("AES", 256, "GCM", F.ENCRYPT, Q.SAFE, Q.SAFE),
    ("AES", 256, "cbc", F.ENCRYPT, Q.SAFE, Q.MEDIUM),
    ("AES", 128, "CCM_8", F.ENCRYPT, Q.MEDIUM, Q.MEDIUM),
    ("NULL", None, None, F.ENCRYPT, Q.UNKNOWN, Q.CRITICAL),
    ("NONE", None, None, F.ENCRYPT, Q.UNKNOWN, Q.CRITICAL),
    ("DES", 56, "CBC", F.ENCRYPT, Q.CRITICAL, Q.CRITICAL),
    ("3DES", 168, "CBC", F.ENCRYPT, Q.CRITICAL, Q.CRITICAL),
    ("RC4", 128, None, F.ENCRYPT, Q.CRITICAL, Q.CRITICAL),
    ("ChaCha20", 256, None, F.ENCRYPT, Q.SAFE, Q.SAFE),
    ("ChaCha20-Poly1305", 256, None, F.ENCRYPT, Q.SAFE, Q.SAFE),
    ("MD5", None, None, F.DIGEST, Q.CRITICAL, Q.CRITICAL),
    ("SHA-1", None, None, F.DIGEST, Q.CRITICAL, Q.CRITICAL),
    ("SHA-256", None, None, F.DIGEST, Q.MEDIUM, Q.SAFE),
    ("SHA-384", None, None, F.DIGEST, Q.SAFE, Q.SAFE),
    ("SHA-512", None, None, F.DIGEST, Q.SAFE, Q.SAFE),
    ("HMAC-SHA-1", None, None, F.MAC, Q.MEDIUM, Q.MEDIUM),
    ("HMAC-MD5", None, None, F.MAC, Q.MEDIUM, Q.MEDIUM),
    ("HMAC-SHA-256", None, None, F.MAC, Q.UNKNOWN, Q.UNKNOWN),
    ("HKDF_SHA-384", None, None, F.KDF, Q.UNKNOWN, Q.UNKNOWN),
    ("TLS-PRF-SHA-256", None, None, F.KDF, Q.UNKNOWN, Q.UNKNOWN),
    ("TLS-PRF-MD5-SHA-1", None, None, F.KDF, Q.MEDIUM, Q.MEDIUM),
    ("ML-KEM-768", None, None, F.KEY_EXCHANGE, Q.SAFE, Q.SAFE),
    ("X25519MLKEM768", None, None, F.KEY_EXCHANGE, Q.SAFE, Q.SAFE),
    ("X25519Kyber768Draft00", None, None, F.KEY_EXCHANGE, Q.UNKNOWN, Q.MEDIUM),
    ("ML-DSA-65", None, None, F.SIGN, Q.SAFE, Q.SAFE),
    ("RSA", None, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.UNKNOWN),
    ("RSA", 1024, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.CRITICAL),
    ("RSA", 2048, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.MEDIUM),
    ("RSA", 2048, None, F.SIGN, Q.CRITICAL, Q.SAFE),
    ("DHE", None, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.UNKNOWN),
    ("DHE-ffdhe2048", 2048, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.SAFE),
    ("ECDHE", None, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.UNKNOWN),
    ("ECDSA", 192, None, F.SIGN, Q.CRITICAL, Q.CRITICAL),
    ("ECDSA", 256, None, F.SIGN, Q.CRITICAL, Q.SAFE),
    ("ECDHE-X25519", 255, None, F.KEY_EXCHANGE, Q.CRITICAL, Q.SAFE),
    ("Ed25519", None, None, F.SIGN, Q.CRITICAL, Q.SAFE),
    ("Ed448", 448, None, F.SIGN, Q.CRITICAL, Q.SAFE),
])
def test_local_risk_policy_with_unknown_and_known_parameters(name, bits, mode, function, quantum, classical):
    """Verifica a politica local de risco e preserva desconhecidos sem declarar uma ligacao segura."""
    actual_quantum, actual_classical, reason, recommendation = risk.assess_primitive(name, bits, mode, function)
    assert (actual_quantum, actual_classical) == (quantum, classical)
    assert reason.strip() and recommendation.strip()


@pytest.mark.parametrize("bits,quantum", [(128, Q.MEDIUM), (192, Q.MEDIUM), (256, Q.SAFE)])
@pytest.mark.parametrize("mode", [None, "", "   ", "INVALID", "future-mode", 123])
def test_aes_unknown_mode_does_not_claim_classical_safety(bits, quantum, mode):
    """Mantem risco classico desconhecido sem perder a avaliacao quantica do tamanho AES."""
    actual_quantum, classical, reason, recommendation = risk.assess_primitive(
        "AES", bits, mode, F.ENCRYPT,
    )
    assert actual_quantum == quantum
    assert classical == Q.UNKNOWN
    assert "mode is missing or unsupported" in reason
    assert recommendation


@pytest.mark.parametrize("mode,classical", [
    ("GCM", Q.SAFE), (" gcm ", Q.SAFE), ("CCM", Q.SAFE),
    ("ctr", Q.SAFE), ("CBC", Q.MEDIUM), (" ccm_8 ", Q.MEDIUM),
])
def test_aes_recognized_modes_preserve_existing_policy(mode, classical):
    """Normaliza o modo AES e preserva a politica dos modos reconhecidos."""
    quantum, actual_classical, reason, _ = risk.assess_primitive("AES", 256, mode, F.ENCRYPT)
    assert (quantum, actual_classical) == (Q.SAFE, classical)
    assert "mode is missing or unsupported" not in reason


@pytest.mark.parametrize("observation", ["declared", "configured", "advertised", "negotiated", "observed"])
def test_finding_model_serialization_and_assessment(observation):
    """Cria um model valido e preserva o tipo de observacao ao aplicar a politica de risco."""
    finding = risk.make_finding(
        Path("sample.pcap"), {"packet_number": 4}, algorithm_name="RSA",
        rule_id="CHECK-RSA", observation=observation, key_size=2048,
        crypto_function=F.SIGN, padding="PSS", protocol="TLS 1.3",
    )
    payload = finding.to_dict()
    assert payload["source_type"] == "network-capture"
    assert payload["observation"] == observation
    assert payload["crypto_function"] == "sign" and payload["padding"] == "PSS"
    assert payload["quantum_risk"] == "critical" and payload["classical_risk"] == "safe"
    assert finding.evidence[0].packet_number == 4
    assert finding.evidence[0].risk_reasoning and finding.recommendation
    assert CryptoFinding.model_validate(json.loads(json.dumps(payload))) == finding


@pytest.mark.parametrize("name,bits,function,quantum,classical,missing_size", [
    ("RSA", None, F.KEY_EXCHANGE, Q.CRITICAL, Q.UNKNOWN, True),
    ("RSA", 1024, F.KEY_EXCHANGE, Q.CRITICAL, Q.CRITICAL, False),
    ("RSA", 2048, F.KEY_EXCHANGE, Q.CRITICAL, Q.MEDIUM, False),
    ("RSA", None, F.SIGN, Q.CRITICAL, Q.UNKNOWN, True),
    ("RSA", 2048, F.SIGN, Q.CRITICAL, Q.SAFE, False),
    ("ECDSA", None, F.SIGN, Q.CRITICAL, Q.UNKNOWN, True),
    ("ECDSA", 256, F.SIGN, Q.CRITICAL, Q.SAFE, False),
    ("DHE", None, F.KEY_EXCHANGE, Q.CRITICAL, Q.UNKNOWN, True),
    ("DHE", 2048, F.KEY_EXCHANGE, Q.CRITICAL, Q.SAFE, False),
    ("Ed25519", None, F.SIGN, Q.CRITICAL, Q.SAFE, False),
    ("Ed448", None, F.SIGN, Q.CRITICAL, Q.SAFE, False),
])
def test_public_key_reasoning_matches_available_size(name, bits, function, quantum, classical, missing_size):
    """Menciona tamanho desconhecido apenas quando falta informacao e preserva as classificacoes."""
    actual_quantum, actual_classical, reason, _ = risk.assess_primitive(
        name, bits, crypto_function=function,
    )
    assert (actual_quantum, actual_classical) == (quantum, classical)
    mentions_missing_size = "size is unknown" in reason or "missing key or group size" in reason.lower()
    assert mentions_missing_size is missing_size
    if name == "RSA" and function == F.KEY_EXCHANGE:
        assert "provides no forward secrecy" in reason
        assert ("not inferred from" in reason) is missing_size


def test_risk_override_and_optional_finding_fields():
    """Respeita uma avaliacao explicita e preserva campos opcionais desconhecidos."""
    finding = risk.make_finding(
        Path("sample.pcap"), {}, algorithm_name="TLS 1.3", rule_id="CHECK-VERSION",
        observation="observed", asset_type=AssetType.PROTOCOL, confidence="low",
        risk_override=(Q.UNKNOWN, Q.MEDIUM, "Explicit policy", "Review protocol"),
    )
    assert finding.asset_type == AssetType.PROTOCOL and finding.confidence == "low"
    assert (finding.quantum_risk, finding.classical_risk) == (Q.UNKNOWN, Q.MEDIUM)
    assert finding.evidence[0].risk_reasoning == "Explicit policy"
    assert finding.recommendation == "Review protocol"
    assert "key_size" not in finding.to_dict()


@pytest.mark.parametrize("changes", [
    {"algorithm_name": ""}, {"key_size": 0}, {"observation": "invalid"},
    {"confidence": "invalid"}, {"rule_id": ""},
])
def test_finding_rejects_invalid_shared_contract_fields(changes):
    """Confirma que resultados invalidos sao rejeitados pelos models comuns."""
    kwargs = {"algorithm_name": "unknown", "rule_id": "CHECK", "observation": "observed", **changes}
    with pytest.raises(ValidationError):
        risk.make_finding(Path("sample.pcap"), {}, **kwargs)


def test_enrichment_preserves_observations_and_independent_packet_evidence():
    finding = CryptoFinding(
        algorithm_name="AES", source_type="network-capture", key_size=256,
        mode="GCM", crypto_function=F.ENCRYPT, observation="advertised",
        protocol="TLS 1.3", confidence="high",
        evidence=[
            Evidence(file_path="sample.pcap", packet_number=4, rule_id="CLIENT"),
            Evidence(file_path="sample.pcap", packet_number=5, rule_id="SERVER"),
        ],
    )
    before = finding.model_dump()
    assessed = risk.enrich_finding(finding)

    assert (assessed.quantum_risk, assessed.classical_risk) == (Q.SAFE, Q.SAFE)
    assert assessed.observation == "advertised" and assessed.confidence == "high"
    assert assessed.protocol == "TLS 1.3" and assessed.key_size == 256
    assert [e.packet_number for e in assessed.evidence] == [4, 5]
    assert [e.rule_id for e in assessed.evidence] == ["CLIENT", "SERVER"]
    assert all(e.risk_reasoning for e in assessed.evidence)
    assert assessed.recommendation
    assert finding.model_dump() == before
    assert assessed is not finding and assessed.evidence[0] is not finding.evidence[0]


def test_enrichment_validates_explicit_risk_labels():
    finding = CryptoFinding(
        algorithm_name="future-protocol", source_type="network-capture",
        asset_type=AssetType.PROTOCOL, observation="observed",
        evidence=[Evidence(file_path="sample.pcap", rule_id="CHECK")],
    )
    with pytest.raises(ValidationError):
        risk.enrich_finding(
            finding, risk_override=("invalid", Q.UNKNOWN, "Reason", "Recommendation"),
        )

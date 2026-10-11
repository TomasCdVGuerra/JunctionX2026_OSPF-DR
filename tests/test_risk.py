from pathlib import Path

import pytest

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel
from scanner.risk import (
    RISK_ASSESSMENT_RULE_ID,
    enrich_finding,
    enrich_findings,
    evaluate_classical_risk,
    evaluate_quantum_risk,
)


@pytest.mark.parametrize(
    "algorithm",
    [
        "RSA",
        "EC",
        "ECDSA",
        "ECDH",
        "ecdhe",
        "DSA",
        "DH",
        "Ed25519",
        "X25519",
    ],
)
def test_shor_vulnerable_families(algorithm):
    risk, reasoning = evaluate_quantum_risk(algorithm)

    assert risk == QuantumRiskLevel.CRITICAL
    assert "Shor" in reasoning
    assert "tamanho de chave desconhecido" in reasoning


@pytest.mark.parametrize("key_size", [1024, 2048, 4096, None])
def test_rsa_size_does_not_remove_quantum_risk(key_size):
    risk, reasoning = evaluate_quantum_risk("RSA", key_size)

    assert risk == QuantumRiskLevel.CRITICAL
    assert "fatorização de inteiros" in reasoning

    if key_size is not None:
        assert f"{key_size} bits" in reasoning


@pytest.mark.parametrize(
    "algorithm",
    [
        None,
        "AES",
        "SHA-256",
        "FutureAlgorithm",
        "TLS_AES_256_GCM_SHA384",
    ],
)
def test_unimplemented_quantum_rules_remain_unknown(algorithm):
    risk, reasoning = evaluate_quantum_risk(algorithm)

    assert risk == QuantumRiskLevel.UNKNOWN
    assert reasoning


@pytest.mark.parametrize("key_size", [0, -1, "2048", True])
def test_invalid_key_size(key_size):
    with pytest.raises(ValueError, match="key_size"):
        evaluate_quantum_risk("RSA", key_size)


@pytest.mark.parametrize(
    "algorithm,key_size,expected",
    [
        ("AES", 128, QuantumRiskLevel.MEDIUM),
        ("AES", 192, QuantumRiskLevel.MEDIUM),
        ("aes", 256, QuantumRiskLevel.SAFE),
        ("SM4", 128, QuantumRiskLevel.MEDIUM),
        ("ChaCha20", 256, QuantumRiskLevel.SAFE),
        ("chacha20-poly1305", 256, QuantumRiskLevel.SAFE),
        ("CHACHA20_POLY1305", 256, QuantumRiskLevel.SAFE),
    ],
)
def test_symmetric_quantum_risk(algorithm, key_size, expected):
    risk, reasoning = evaluate_quantum_risk(algorithm, key_size)

    assert risk == expected
    assert "Grover" in reasoning
    assert f"{key_size} bits" in reasoning


@pytest.mark.parametrize(
    "algorithm",
    ["AES", "SM4", "ChaCha20", "ChaCha20-Poly1305"],
)
def test_symmetric_missing_key_size_remains_unknown(algorithm):
    risk, reasoning = evaluate_quantum_risk(algorithm)

    assert risk == QuantumRiskLevel.UNKNOWN
    assert "tamanho de chave desconhecido" in reasoning


@pytest.mark.parametrize(
    "algorithm,key_size",
    [
        ("AES", 160),
        ("SM4", 256),
        ("ChaCha20", 128),
        ("ChaCha20-Poly1305", 128),
    ],
)
def test_unrecognised_symmetric_key_size_remains_unknown(
    algorithm, key_size
):
    risk, reasoning = evaluate_quantum_risk(algorithm, key_size)

    assert risk == QuantumRiskLevel.UNKNOWN
    assert "não reconhecido" in reasoning


@pytest.mark.parametrize(
    "algorithm,family,digest",
    [
        ("SHA1WITHRSA", "RSA", "SHA-1"),
        ("sha256WithRSA", "RSA", "SHA-256"),
        ("SHA384WITHRSA", "RSA", "SHA-384"),
        ("SHA512WITHRSA", "RSA", "SHA-512"),
        ("ECDSAWITHSHA256", "ECDSA", "SHA-256"),
        ("SHA384WITHECDSA", "ECDSA", "SHA-384"),
        ("ECDSAWITHSHA512", "ECDSA", "SHA-512"),
    ],
)
def test_composite_signatures_are_quantum_critical(
    algorithm, family, digest
):
    risk, reasoning = evaluate_quantum_risk(algorithm)

    assert risk == QuantumRiskLevel.CRITICAL
    assert family in reasoning
    assert digest in reasoning
    assert "Shor" in reasoning


@pytest.mark.parametrize(
    "suite",
    [
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
    ],
)
def test_legacy_suites_have_critical_asymmetric_components(suite):
    risk, reasoning = evaluate_quantum_risk(suite)

    assert risk == QuantumRiskLevel.CRITICAL
    assert "Troca de chaves:" in reasoning
    assert "Autenticação:" in reasoning
    assert "Shor" in reasoning


@pytest.mark.parametrize(
    "suite,symmetric_classification",
    [
        ("TLS_AES_128_GCM_SHA256", "medium"),
        ("TLS_AES_256_GCM_SHA384", "safe"),
        ("TLS_CHACHA20_POLY1305_SHA256", "safe"),
    ],
)
def test_tls13_suite_does_not_prove_full_quantum_security(
    suite, symmetric_classification
):
    risk, reasoning = evaluate_quantum_risk(suite)

    assert risk == QuantumRiskLevel.UNKNOWN
    assert f"Classificação {symmetric_classification}" in reasoning
    assert "Troca de chaves: não identificada" in reasoning
    assert "Autenticação: não identificada" in reasoning
    assert "hkdf" in reasoning
    assert "Shor" not in reasoning


@pytest.mark.parametrize(
    "algorithm",
    [
        "SHA256WITHFutureAlgorithm",
        "TLS_AES_512_GCM_SHA384",
        "ECDHE-RSA-FUTURE-SHA256",
    ],
)
def test_unknown_composite_names_are_not_guessed(algorithm):
    risk, reasoning = evaluate_quantum_risk(algorithm)

    assert risk == QuantumRiskLevel.UNKNOWN
    assert algorithm in reasoning


@pytest.mark.parametrize(
    "algorithm,key_size,expected",
    [
        ("RSA", 1024, QuantumRiskLevel.CRITICAL),
        ("RSA", 2047, QuantumRiskLevel.CRITICAL),
        ("RSA", 2048, QuantumRiskLevel.SAFE),
        ("RSA", 4096, QuantumRiskLevel.SAFE),
        ("RSA", None, QuantumRiskLevel.UNKNOWN),
        ("EC", 192, QuantumRiskLevel.CRITICAL),
        ("EC", 224, QuantumRiskLevel.SAFE),
        ("ECDSA", 256, QuantumRiskLevel.SAFE),
        ("ECDHE", None, QuantumRiskLevel.UNKNOWN),
        ("EC", 999, QuantumRiskLevel.UNKNOWN),
        ("DH", 2048, QuantumRiskLevel.UNKNOWN),
        ("DSA", 2048, QuantumRiskLevel.UNKNOWN),
        ("FutureAlgorithm", 256, QuantumRiskLevel.UNKNOWN),
    ],
)
def test_classical_key_strength_and_missing_parameters(algorithm, key_size, expected):
    risk, reasoning = evaluate_classical_risk(algorithm, key_size)
    assert risk == expected
    assert reasoning


@pytest.mark.parametrize(
    "algorithm,key_size,mode,expected",
    [
        ("AES", 128, "GCM", QuantumRiskLevel.SAFE),
        ("AES", 256, "ecb", QuantumRiskLevel.CRITICAL),
        ("AES", None, "ECB", QuantumRiskLevel.CRITICAL),
        ("AES", 256, "CBC", QuantumRiskLevel.MEDIUM),
        ("AES", None, "GCM", QuantumRiskLevel.UNKNOWN),
        ("AES", 160, None, QuantumRiskLevel.UNKNOWN),
        ("AES", 256, "FutureMode", QuantumRiskLevel.UNKNOWN),
        ("SM4", 128, "GCM", QuantumRiskLevel.SAFE),
        ("ChaCha20-Poly1305", 256, None, QuantumRiskLevel.SAFE),
        ("ChaCha20-Poly1305", 256, "GCM", QuantumRiskLevel.UNKNOWN),
        ("DES", None, None, QuantumRiskLevel.CRITICAL),
        ("3DES", 168, None, QuantumRiskLevel.CRITICAL),
    ],
)
def test_classical_symmetric_rules(algorithm, key_size, mode, expected):
    risk, reasoning = evaluate_classical_risk(algorithm, key_size, mode=mode)
    assert risk == expected
    assert reasoning


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-1"])
@pytest.mark.parametrize(
    "function,expected",
    [
        (CryptoFunction.DIGEST, QuantumRiskLevel.CRITICAL),
        (CryptoFunction.SIGN, QuantumRiskLevel.CRITICAL),
        (CryptoFunction.VERIFY, QuantumRiskLevel.CRITICAL),
        (CryptoFunction.MAC, QuantumRiskLevel.UNKNOWN),
        (CryptoFunction.KDF, QuantumRiskLevel.UNKNOWN),
        (CryptoFunction.UNKNOWN, QuantumRiskLevel.UNKNOWN),
    ],
)
def test_classical_weak_hash_requires_usage_context(algorithm, function, expected):
    risk, reasoning = evaluate_classical_risk(algorithm, crypto_function=function)
    assert risk == expected
    assert function.value in reasoning


@pytest.mark.parametrize("algorithm", ["SHA-224", "SHA-256", "SHA-384", "SHA-512"])
def test_classical_sha2_is_scoped_to_hash_strength(algorithm):
    risk, reasoning = evaluate_classical_risk(algorithm)
    assert risk == QuantumRiskLevel.SAFE
    assert "não avalia" in reasoning


@pytest.mark.parametrize(
    "algorithm,expected",
    [
        ("TLSv1.0", QuantumRiskLevel.CRITICAL),
        ("tls1.1", QuantumRiskLevel.CRITICAL),
        ("TLSv1.2", QuantumRiskLevel.SAFE),
        ("TLSv1.3", QuantumRiskLevel.SAFE),
        ("TLS", QuantumRiskLevel.UNKNOWN),
        ("HTTPS", QuantumRiskLevel.UNKNOWN),
        ("TLSv9.9", QuantumRiskLevel.UNKNOWN),
    ],
)
def test_classical_protocol_version(algorithm, expected):
    risk, reasoning = evaluate_classical_risk(algorithm)
    assert risk == expected
    assert reasoning


@pytest.mark.parametrize(
    "signature,key_size,expected",
    [
        ("SHA1WITHRSA", None, QuantumRiskLevel.CRITICAL),
        ("SHA256WITHRSA", None, QuantumRiskLevel.UNKNOWN),
        ("SHA256WITHRSA", 1024, QuantumRiskLevel.CRITICAL),
        ("SHA256WITHRSA", 2048, QuantumRiskLevel.SAFE),
        ("ECDSAWITHSHA256", 256, QuantumRiskLevel.SAFE),
    ],
)
def test_classical_signature_combines_key_and_hash(signature, key_size, expected):
    risk, reasoning = evaluate_classical_risk(signature, key_size)
    assert risk == expected
    assert "Chave:" in reasoning
    assert "Hash:" in reasoning


@pytest.mark.parametrize(
    "suite",
    [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "AES128-SHA",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ],
)
def test_classical_suite_does_not_invent_asymmetric_parameters(suite):
    # A single external size cannot describe RSA, EC and AES simultaneously.
    risk, reasoning = evaluate_classical_risk(suite, 4096)
    assert risk == QuantumRiskLevel.UNKNOWN
    assert "4096" not in reasoning
    assert "Troca de chaves:" in reasoning
    assert "Autenticação:" in reasoning
    assert "colisões comprometida" not in reasoning


def test_quantum_and_classical_risks_are_independent():
    assert evaluate_quantum_risk("RSA", 2048)[0] == QuantumRiskLevel.CRITICAL
    assert evaluate_classical_risk("RSA", 2048)[0] == QuantumRiskLevel.SAFE
    assert evaluate_quantum_risk("AES", 128)[0] == QuantumRiskLevel.MEDIUM
    assert evaluate_classical_risk("AES", 128)[0] == QuantumRiskLevel.SAFE
    assert evaluate_quantum_risk("AES", 256)[0] == QuantumRiskLevel.SAFE
    assert evaluate_classical_risk("AES", 256, mode="ECB")[0] == QuantumRiskLevel.CRITICAL


@pytest.mark.parametrize("key_size", [0, -1, "2048", True])
def test_classical_invalid_key_size(key_size):
    with pytest.raises(ValueError, match="key_size"):
        evaluate_classical_risk("RSA", key_size)


@pytest.mark.parametrize("mode", ["", "  ", 123, True])
def test_classical_invalid_mode(mode):
    with pytest.raises(ValueError, match="mode"):
        evaluate_classical_risk("AES", 256, mode=mode)


@pytest.fixture
def rsa_finding():
    return CryptoFinding(
        algorithm_name="RSA",
        key_size=2048,
        asset_type=AssetType.KEY,
        source_type="cloud-posture",
        observation="configured",
        confidence="high",
        recommendation="Recomendação existente",
        evidence=[
            Evidence(
                file_path="kms.json",
                json_path="$.Keys[0]",
                matched_snippet='{"KeySpec": "RSA_2048"}',
                rule_id="AWS-KMS-KEY-SPEC",
                risk_reasoning="Justificação original do scanner",
            ),
            Evidence(
                file_path="metadata.json",
                json_path="$.Account",
                rule_id="TEST-METADATA",
            ),
        ],
    )


def test_enrichment_preserves_original_and_records_both_assessments(rsa_finding):
    before = rsa_finding.model_dump()
    enriched = enrich_finding(rsa_finding)

    assert rsa_finding.model_dump() == before
    assert enriched is not rsa_finding
    assert enriched.quantum_risk == QuantumRiskLevel.CRITICAL
    assert enriched.classical_risk == QuantumRiskLevel.SAFE
    assert enriched.evidence[:-1] == rsa_finding.evidence
    assert enriched.model_dump(exclude={"quantum_risk", "classical_risk", "evidence"}) == (
        rsa_finding.model_dump(exclude={"quantum_risk", "classical_risk", "evidence"})
    )

    assessment = enriched.evidence[-1]
    assert assessment.rule_id == RISK_ASSESSMENT_RULE_ID
    assert assessment.file_path == "kms.json"
    assert assessment.json_path == "$.Keys[0]"
    assert assessment.matched_snippet is None
    assert assessment.nist_standard is None
    assert "Risco quântico (critical):" in assessment.risk_reasoning
    assert "Risco clássico (safe):" in assessment.risk_reasoning
    assert "Shor" in assessment.risk_reasoning
    assert enriched.evidence[0].risk_reasoning == "Justificação original do scanner"

    # Nested evidence must also be copied, rather than shared with the scanner.
    enriched.evidence[0].matched_snippet = "Alterado na cópia"
    assert rsa_finding.model_dump() == before


def test_enrichment_is_idempotent(rsa_finding):
    once = enrich_finding(rsa_finding)
    twice = enrich_finding(once)
    assert twice == once
    assert len(twice.evidence) == len(rsa_finding.evidence) + 1
    assert sum(e.rule_id == RISK_ASSESSMENT_RULE_ID for e in twice.evidence) == 1


def test_enrichment_updates_previous_assessment_when_parameters_change(rsa_finding):
    first = enrich_finding(rsa_finding)
    first.key_size = 1024
    second = enrich_finding(first)
    assert first.classical_risk == QuantumRiskLevel.SAFE
    assert second.classical_risk == QuantumRiskLevel.CRITICAL
    assert "1024 bits" in second.evidence[-1].risk_reasoning
    assert "RSA, 2048 bits:" not in second.evidence[-1].risk_reasoning
    assert second.evidence[-1].risk_reasoning != first.evidence[-1].risk_reasoning
    assert second.evidence[:-1] == first.evidence[:-1]


@pytest.mark.parametrize(
    "source_type,observation,location",
    [
        ("source-code", "declared", {"line_number": 10}),
        ("cloud-posture", "configured", {"json_path": "$.Keys[0]"}),
        ("network-capture", "negotiated", {"packet_number": 42}),
    ],
)
def test_enrichment_works_for_all_source_locations(source_type, observation, location):
    finding = CryptoFinding(
        algorithm_name="AES", key_size=256,
        source_type=source_type, observation=observation,
        evidence=[Evidence(file_path="input", rule_id="TEST-SOURCE", **location)],
    )
    enriched = enrich_finding(finding)
    for field, value in location.items():
        assert getattr(enriched.evidence[-1], field) == value
    assert enriched.source_type == source_type
    assert enriched.observation == observation


@pytest.mark.parametrize(
    "function,expected",
    [(CryptoFunction.SIGN, QuantumRiskLevel.CRITICAL),
     (CryptoFunction.MAC, QuantumRiskLevel.UNKNOWN)],
)
def test_enrichment_passes_hash_usage_context(rsa_finding, function, expected):
    finding = rsa_finding.model_copy(update={
        "algorithm_name": "SHA-1", "key_size": None, "crypto_function": function,
    })
    assert enrich_finding(finding).classical_risk == expected


def test_enrichment_passes_mode_without_mixing_quantum_risk(rsa_finding):
    finding = rsa_finding.model_copy(update={
        "algorithm_name": "AES", "key_size": 256, "mode": "ECB",
    })
    enriched = enrich_finding(finding)
    assert enriched.quantum_risk == QuantumRiskLevel.SAFE
    assert enriched.classical_risk == QuantumRiskLevel.CRITICAL


def test_enrichment_recomputes_unknown_without_inventing_parameters(rsa_finding):
    finding = rsa_finding.model_copy(update={
        "algorithm_name": "FutureAlgorithm", "key_size": None,
        "quantum_risk": QuantumRiskLevel.SAFE,
        "classical_risk": QuantumRiskLevel.SAFE,
    })
    enriched = enrich_finding(finding)
    assert enriched.quantum_risk == QuantumRiskLevel.UNKNOWN
    assert enriched.classical_risk == QuantumRiskLevel.UNKNOWN
    assert enriched.key_size is None
    assert enriched.confidence == finding.confidence
    assert finding.quantum_risk == QuantumRiskLevel.SAFE


def test_batch_enrichment_preserves_order_and_contract(rsa_finding):
    aes = rsa_finding.model_copy(update={"algorithm_name": "AES", "key_size": 128})
    findings = [rsa_finding, aes]
    enriched = enrich_findings(findings)
    assert [f.algorithm_name for f in enriched] == ["RSA", "AES"]
    assert len(enriched) == len(findings)
    assert all(new is not old for new, old in zip(enriched, findings))
    assert enriched[1].quantum_risk == QuantumRiskLevel.MEDIUM
    assert enriched[1].classical_risk == QuantumRiskLevel.SAFE
    for finding in enriched:
        assert CryptoFinding.model_validate(finding.to_dict()) == finding
    assert enrich_findings([]) == []


def test_enrichment_requires_scanner_evidence(rsa_finding):
    finding = rsa_finding.model_copy(update={"evidence": [Evidence(
        file_path="input", rule_id=RISK_ASSESSMENT_RULE_ID,
    )]})
    with pytest.raises(ValueError, match="evidência original"):
        enrich_finding(finding)


def test_real_cloud_inventory_can_be_enriched_without_changing_discovery():
    from scanner.cloud_scanner import scan

    directory = Path(__file__).resolve().parents[1] / "support-materials" / "cloud-posture"
    originals = scan(directory)
    before = [finding.model_dump() for finding in originals]
    enriched = enrich_findings(originals)

    assert len(enriched) == len(originals) == 99
    assert [finding.model_dump() for finding in originals] == before
    assert all(finding.quantum_risk == QuantumRiskLevel.UNKNOWN for finding in originals)
    assert any(finding.quantum_risk == QuantumRiskLevel.CRITICAL for finding in enriched)
    assert any(finding.classical_risk == QuantumRiskLevel.CRITICAL for finding in enriched)
    assert enrich_findings(enriched) == enriched
    for original, result in zip(originals, enriched):
        assert result.evidence[:-1] == original.evidence
        assert len(result.evidence) == len(original.evidence) + 1
        assert result.key_size == original.key_size
        assert result.algorithm_name == original.algorithm_name

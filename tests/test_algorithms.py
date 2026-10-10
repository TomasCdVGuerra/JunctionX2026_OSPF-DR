"""Tests for algorithm risk evaluation engine, NIST mappings, and taxonomy."""

from __future__ import annotations

from scanner.algorithms import get_primitive_category, is_pqc_native, normalise, oid_for
from scanner.models import CryptoFinding, Evidence, QuantumRiskLevel
from scanner.risk import (
    algorithm_family,
    build_reasoning,
    enrich_finding_risk,
    evaluate_risk,
    is_classically_broken,
    is_shor_vulnerable,
    map_nist_standard,
)


def _assert_single_sentence(reasoning: str) -> None:
    """Assert reasoning is a non-empty, single-sentence explanation ending with a period."""
    assert reasoning, "Reasoning must not be empty"
    assert "\n" not in reasoning, "Reasoning must be a single line"
    assert reasoning.endswith("."), f"Reasoning must end with a period: {reasoning}"
    # Ensure there isn't multiple sentences joined by periods
    sentences = [s.strip() for s in reasoning.rstrip(".").split(".") if s.strip()]
    assert len(sentences) <= 1, f"Reasoning should be a single sentence: {reasoning}"


# =========================================================================
# 25 Required Risk Tests (from specification)
# =========================================================================

def test_1_rsa_1024_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("RSA-1024", key_size=1024)
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 80
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_2_rsa_2048_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("RSA-2048", key_size=2048)
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 112
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_3_rsa_4096_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("RSA-4096", key_size=4096)
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 152
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_4_ed25519_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("Ed25519")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 128
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_5_ecdsa_p256_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("ECDSA P-256")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 128
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_6_ecdsa_p384_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("ECDSA P-384")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 192
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_7_ecdh_is_critical():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("ECDH")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_8_curve25519_is_critical():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("Curve25519")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    assert cl_bits == 128
    _assert_single_sentence(reasoning)
    assert "Shor" in reasoning


def test_9_md5_is_critical():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("MD5")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    _assert_single_sentence(reasoning)
    assert "collision" in reasoning.lower()


def test_10_sha1_is_critical():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("SHA-1")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    _assert_single_sentence(reasoning)
    assert "collision" in reasoning.lower()


def test_11_aes_ecb_is_critical():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("AES-ECB", mode="ECB")
    assert risk == QuantumRiskLevel.CRITICAL
    assert q_bits == 0
    _assert_single_sentence(reasoning)
    assert "pattern" in reasoning.lower() or "leak" in reasoning.lower()


def test_12_aes_128_gcm_is_medium():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("AES-128-GCM", key_size=128, mode="GCM")
    assert risk == QuantumRiskLevel.MEDIUM
    assert q_bits == 64
    assert cl_bits == 128
    _assert_single_sentence(reasoning)
    assert "Grover" in reasoning


def test_13_aes_256_gcm_is_safe():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("AES-256-GCM", key_size=256, mode="GCM")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits == 128
    assert cl_bits == 256
    _assert_single_sentence(reasoning)
    assert "Grover" in reasoning


def test_14_sha_256_is_safe():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("SHA-256")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits == 128
    assert cl_bits == 128
    _assert_single_sentence(reasoning)


def test_15_sha_384_is_safe():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("SHA-384")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits == 192
    assert cl_bits == 192
    _assert_single_sentence(reasoning)


def test_16_sha_512_is_safe():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("SHA-512")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits == 256
    assert cl_bits == 256
    _assert_single_sentence(reasoning)


def test_17_hmac_sha256_is_safe():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("HMAC-SHA256")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits == 128
    _assert_single_sentence(reasoning)


def test_18_pbkdf2_hmac_sha256_is_safe():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("PBKDF2-HMAC-SHA256")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits == 128
    _assert_single_sentence(reasoning)


def test_19_ml_kem_is_safe():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("ML-KEM-768")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits >= 128
    _assert_single_sentence(reasoning)
    assert "FIPS 203" in reasoning


def test_20_ml_dsa_is_safe():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("ML-DSA-65")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits >= 128
    _assert_single_sentence(reasoning)
    assert "FIPS 204" in reasoning


def test_21_slh_dsa_is_safe():
    risk, _cl_bits, q_bits, reasoning = evaluate_risk("SLH-DSA")
    assert risk == QuantumRiskLevel.SAFE
    assert q_bits >= 128
    _assert_single_sentence(reasoning)
    assert "FIPS 205" in reasoning


def test_22_unknown_algorithm_is_unknown():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("MyCustomCipher2026")
    assert risk == QuantumRiskLevel.UNKNOWN
    assert cl_bits is None
    assert q_bits is None
    _assert_single_sentence(reasoning)


def test_23_unknown_aes_key_size_is_unknown():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("AES", key_size=None)
    assert risk == QuantumRiskLevel.UNKNOWN
    assert cl_bits is None
    assert q_bits is None
    _assert_single_sentence(reasoning)


def test_24_unknown_mode_is_unknown():
    risk, cl_bits, q_bits, reasoning = evaluate_risk("AES-128", mode="unknown")
    assert risk == QuantumRiskLevel.UNKNOWN
    assert cl_bits is None
    assert q_bits is None
    _assert_single_sentence(reasoning)


def test_25_all_results_have_single_sentence_reasoning():
    test_cases = [
        "RSA-3072",
        "EdDSA",
        "ECC-NIST-P521",
        "EC prime256v1",
        "EC secp384r1",
        "X25519",
        "Diffie-Hellman",
        "DSA",
        "DES",
        "3DES",
        "AES-128-CBC",
        "AES-128-CTR",
        "Kyber",
        "Dilithium",
        "SPHINCS+",
    ]
    for algo in test_cases:
        _risk, _, _, reasoning = evaluate_risk(algo)
        _assert_single_sentence(reasoning)
        helper_reasoning = build_reasoning(algo)
        assert helper_reasoning == reasoning


# =========================================================================
# NIST Standard Mappings
# =========================================================================

def test_map_nist_standards():
    assert map_nist_standard("ML-KEM-768") == "FIPS 203"
    assert map_nist_standard("Kyber-512") == "FIPS 203"
    assert map_nist_standard("ML-DSA-65") == "FIPS 204"
    assert map_nist_standard("Dilithium3") == "FIPS 204"
    assert map_nist_standard("SLH-DSA") == "FIPS 205"
    assert map_nist_standard("SPHINCS+") == "FIPS 205"
    assert map_nist_standard("RSA-2048") == "FIPS 186-5"
    assert map_nist_standard("ECDSA P-256") == "FIPS 186-5"
    assert map_nist_standard("SHA-256") == "FIPS 180-4"
    assert map_nist_standard("SHA-384") == "FIPS 180-4"
    assert map_nist_standard("SHA-512") == "FIPS 180-4"
    assert map_nist_standard("AES-256-GCM") == "FIPS 197"
    assert map_nist_standard("HMAC-SHA256") == "FIPS 198-1"
    assert map_nist_standard("PBKDF2") == "SP 800-132"
    assert map_nist_standard("CustomCipher") == "none"
    assert map_nist_standard("") == "none"


# =========================================================================
# Algorithm Normalization, OIDs, and Helper Functions
# =========================================================================

def test_algorithm_normalization_variations():
    assert normalise("sha-256") == "SHA-256"
    assert normalise("SHA256") == "SHA-256"
    assert normalise("aes_gcm") == "AES-GCM"
    assert normalise("AES/ECB/PKCS5Padding") == "AES-ECB"
    assert normalise("SHA1withRSA") == "SHA1withRSA"
    assert normalise("") == "unknown"


def test_oid_mappings():
    assert oid_for("RSA") == "1.2.840.113549.1.1.1"
    assert oid_for("SHA-256") == "2.16.840.1.101.3.4.2.1"
    assert oid_for("Ed25519") == "1.3.101.112"
    assert oid_for("AES-256-GCM") == "2.16.840.1.101.3.4.1.46"
    assert oid_for("ML-KEM-768") == "2.16.840.1.101.3.4.4.2"
    assert oid_for("NonExistentCipher") == "unknown"


def test_primitive_taxonomies():
    assert get_primitive_category("ML-KEM") == "kem"
    assert get_primitive_category("RSA") == "signature"
    assert get_primitive_category("ECDH") == "key-exchange"
    assert get_primitive_category("AES-256-GCM") == "block-cipher"
    assert get_primitive_category("SHA-256") == "hash"
    assert get_primitive_category("HMAC-SHA256") == "mac"
    assert get_primitive_category("PBKDF2") == "kdf"
    assert is_pqc_native("ML-KEM") is True
    assert is_pqc_native("ML-DSA") is True
    assert is_pqc_native("SLH-DSA") is True
    assert is_pqc_native("RSA") is False


def test_family_and_helpers():
    assert algorithm_family("RSA-4096") == "RSA"
    assert algorithm_family("Ed25519") == "EdDSA"
    assert algorithm_family("AES-128") == "AES"
    assert is_shor_vulnerable("RSA") is True
    assert is_shor_vulnerable("ML-DSA") is False
    assert is_shor_vulnerable("AES-256") is False
    assert is_classically_broken("MD5") is True
    assert is_classically_broken("AES", mode="ECB") is True
    assert is_classically_broken("AES-256", mode="GCM") is False


# =========================================================================
# Finding Enrichment Contract Verification
# =========================================================================

def test_enrich_finding_risk_pydantic_contract():
    finding = CryptoFinding(
        algorithm_name="RSA-2048",
        key_size=2048,
        source_type="source-code",
        observation="observed",
        evidence=[
            Evidence(
                file_path="service.py",
                line_number=42,
                rule_id="src-rsa",
            )
        ],
    )
    enriched = enrich_finding_risk(finding)

    assert enriched.quantum_risk == QuantumRiskLevel.CRITICAL
    assert enriched.classical_risk == QuantumRiskLevel.SAFE
    assert enriched.evidence[0].risk_reasoning is not None
    assert "Shor" in enriched.evidence[0].risk_reasoning
    assert enriched.evidence[0].nist_standard == "FIPS 186-5"
    assert enriched.evidence[0].file_path == "service.py"
    assert enriched.evidence[0].line_number == 42


def test_enrich_finding_risk_does_not_replace_specific_with_unknown():
    finding = CryptoFinding(
        algorithm_name="CustomProprietaryCrypto",
        source_type="source-code",
        observation="observed",
        quantum_risk=QuantumRiskLevel.CRITICAL,
        evidence=[
            Evidence(
                file_path="custom.py",
                line_number=1,
                rule_id="custom-rule",
                risk_reasoning="Known proprietary critical vulnerability.",
            )
        ],
    )
    enriched = enrich_finding_risk(finding)
    # The specific CRITICAL risk from scanner must not be downgraded to UNKNOWN
    assert enriched.quantum_risk == QuantumRiskLevel.CRITICAL
    assert enriched.evidence[0].risk_reasoning == "Known proprietary critical vulnerability."

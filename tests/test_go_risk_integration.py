"""Go naming conventions and central risk evaluation, without scanner changes."""
from pathlib import Path

import pytest

from scanner.algorithms import parse_hash_construction, parse_primitive_name
from scanner.go_scanner import scan
from scanner.models import CryptoFunction, QuantumRiskLevel
from scanner.risk import enrich_findings, evaluate_classical_risk, evaluate_quantum_risk


@pytest.mark.parametrize(
    "name,family,size,mode",
    [
        ("RSA-2048", "RSA", 2048, None),
        ("rsa_4096", "RSA", 4096, None),
        ("AES-256-GCM", "AES", 256, "GCM"),
        ("AES-128-ECB", "AES", 128, "ECB"),
        ("AES-GCM", "AES", None, "GCM"),
        ("AES-unknown", "AES", None, "UNKNOWN"),
    ],
)
def test_go_primitive_names(name, family, size, mode):
    parsed = parse_primitive_name(name)
    assert (parsed.family, parsed.key_size, parsed.mode) == (family, size, mode)


@pytest.mark.parametrize("name", ["NotRSA-2048", "RSA-0", "AES-256-Future", "AES128-GCM-SHA256", "TLS_AES_256_GCM_SHA384"])
def test_primitive_parser_does_not_guess_or_capture_tls_suites(name):
    assert parse_primitive_name(name) is None


@pytest.mark.parametrize(
    "name,size,mode,quantum,classical",
    [
        ("RSA-2048", 2048, None, "critical", "safe"),
        ("RSA-1024", None, None, "critical", "critical"),
        ("AES-256-GCM", None, None, "safe", "safe"),
        ("AES-128-ECB", 128, "ECB", "medium", "critical"),
        ("AES-ECB", None, None, "unknown", "critical"),
        ("AES-GCM", None, "GCM", "unknown", "unknown"),
        ("AES-192-CBC", 192, "CBC", "medium", "medium"),
        ("AES-160-GCM", 160, "GCM", "unknown", "unknown"),
        ("Curve25519", 256, None, "critical", "safe"),
        ("X25519", 255, None, "critical", "safe"),
        ("Ed25519", 256, None, "critical", "safe"),
        ("Ed25519", None, None, "critical", "safe"),
        ("Ed25519", 1024, None, "critical", "unknown"),
    ],
)
def test_go_names_reach_family_rules(name, size, mode, quantum, classical):
    assert evaluate_quantum_risk(name, size, mode=mode)[0].value == quantum
    assert evaluate_classical_risk(name, size, mode=mode)[0].value == classical


@pytest.mark.parametrize(
    "name,size,mode",
    [("RSA-2048", 4096, None), ("AES-128-GCM", 256, "GCM"),
     ("AES-256-GCM", 256, "ECB")],
)
def test_conflicting_name_and_fields_remain_unknown(name, size, mode):
    for evaluate in (evaluate_quantum_risk, evaluate_classical_risk):
        risk, reasoning = evaluate(name, size, mode=mode)
        assert risk == QuantumRiskLevel.UNKNOWN
        assert "contraditórios" in reasoning


@pytest.mark.parametrize(
    "name,construction,hash_name,function",
    [("HMAC-SHA256", "HMAC", "SHA-256", CryptoFunction.MAC),
     ("hmac_sha_256", "HMAC", "SHA-256", CryptoFunction.MAC),
     ("PBKDF2-HMAC-SHA256", "PBKDF2", "SHA-256", CryptoFunction.KDF)],
)
def test_hash_constructions_are_recognised_without_false_security(name, construction, hash_name, function):
    assert parse_hash_construction(name) == (construction, hash_name)
    for evaluate in (evaluate_quantum_risk, evaluate_classical_risk):
        risk, reasoning = evaluate(name, 256, crypto_function=function)
        assert risk == QuantumRiskLevel.UNKNOWN
        assert construction in reasoning and hash_name in reasoning
        assert "entropia" in reasoning
        assert "BHT" not in reasoning


@pytest.mark.parametrize("name", ["NotHMAC-SHA256", "PBKDF2-HMAC-Future", "HMAC-SHA999"])
def test_unknown_hash_constructions_are_preserved(name):
    assert parse_hash_construction(name) is None


def test_real_go_rsa_and_curve_calls_can_be_enriched(tmp_path):
    path = tmp_path / "crypto.go"
    path.write_text(
        'package main\nfunc main() {\n'
        'rsa.GenerateKey(rand.Reader, 2048)\n'
        'curve25519.X25519(secret, basepoint)\n'
        'ed25519.GenerateKey(rand.Reader)\n}\n', encoding="utf-8",
    )
    originals = scan(path)
    before = [finding.model_dump() for finding in originals]
    enriched = enrich_findings(originals)
    assert {f.algorithm_name for f in enriched} == {"RSA-2048", "Curve25519", "Ed25519"}
    assert all(f.quantum_risk == QuantumRiskLevel.CRITICAL for f in enriched)
    assert all(f.classical_risk == QuantumRiskLevel.SAFE for f in enriched)
    assert all(f.recommendation for f in enriched)
    assert [finding.model_dump() for finding in originals] == before
    assert enrich_findings(enriched) == enriched


def test_bundled_go_findings_keep_observations_and_known_rsa_aes_rules():
    directory = Path(__file__).resolve().parents[1] / "support-materials" / "sample-repos"
    originals = scan(directory)
    assert originals
    before = [finding.model_dump() for finding in originals]
    enriched = enrich_findings(originals)
    assert len(enriched) == len(originals)
    assert [finding.model_dump() for finding in originals] == before
    assert enrich_findings(enriched) == enriched
    rsa_results = [f for f in enriched if f.algorithm_name.startswith("RSA-")]
    assert rsa_results
    assert all(f.quantum_risk == QuantumRiskLevel.CRITICAL for f in rsa_results)
    aes_results = [f for f in enriched if f.algorithm_name.startswith("AES-")]
    assert aes_results
    for original, result in zip(originals, enriched):
        assert result.evidence[:-1] == original.evidence
        for field in ("algorithm_name", "key_size", "mode", "crypto_function", "observation"):
            assert getattr(result, field) == getattr(original, field)
        assert result.recommendation
    for result in aes_results:
        if result.mode == "ECB":
            assert result.classical_risk == QuantumRiskLevel.CRITICAL
            assert "AES-256-GCM" in result.recommendation


def test_named_parameters_are_evaluated_without_filling_missing_fields(tmp_path):
    path = tmp_path / "crypto.go"
    path.write_text('package main\nfunc main() { rsa.GenerateKey(rand.Reader, 2048) }', encoding="utf-8")
    original = scan(path)[0]
    original.key_size = None
    result = enrich_findings([original])[0]
    assert result.key_size is None
    assert result.algorithm_name == "RSA-2048"
    assert result.classical_risk == QuantumRiskLevel.SAFE

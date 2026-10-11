"""Equivalent primitive evidence agrees; protocol exceptions remain explicit."""
import pytest

from scanner.models import CryptoFunction as F, QuantumRiskLevel as Q
from scanner.risk import evaluate_quantum_risk, evaluate_classical_risk
from scanner.network_scanner.analyser.risk_assessment import assess_primitive


@pytest.mark.parametrize("name,bits,mode,function", [
    ("AES", 128, "GCM", F.ENCRYPT), ("AES", 256, "GCM", F.ENCRYPT),
    ("AES", 128, "CBC", F.ENCRYPT), ("AES", 256, "ECB", F.ENCRYPT),
    ("AES", None, "ECB", F.ENCRYPT), ("RSA", 2048, None, F.SIGN),
    ("RSA", None, None, F.SIGN), ("SHA-256", None, None, F.DIGEST),
    ("SHA-384", None, None, F.DIGEST), ("HMAC-SHA-256", None, None, F.MAC),
])
def test_equivalent_evidence_has_equivalent_primitive_ratings(name, bits, mode, function):
    quantum = evaluate_quantum_risk(name, bits, mode=mode, crypto_function=function)[0]
    classical = evaluate_classical_risk(name, bits, mode=mode, crypto_function=function)[0]
    assert assess_primitive(name, bits, mode, function)[:2] == (quantum, classical)


def test_rsa_transport_review_is_distinct_from_signature_key_strength():
    quantum, classical, reason, _ = assess_primitive("RSA", 2048, crypto_function=F.KEY_EXCHANGE)
    assert (quantum, classical) == (Q.CRITICAL, Q.MEDIUM)
    assert "no forward secrecy" in reason
    assert assess_primitive("RSA", 2048, crypto_function=F.SIGN)[:2] == (Q.CRITICAL, Q.SAFE)


@pytest.mark.parametrize("name", ["HMAC-SHA-256", "HKDF-SHA-384", "TLS-PRF-SHA-256"])
def test_keyed_network_capabilities_do_not_prove_secret_entropy(name):
    quantum, classical, reason, action = assess_primitive(name)
    assert (quantum, classical) == (Q.UNKNOWN, Q.UNKNOWN)
    assert "entropy" in reason and "entropy" in action

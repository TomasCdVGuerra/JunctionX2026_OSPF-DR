"""Axis-specific summaries retain recorded reasons and uncertainty."""
from scanner.presentation import risk_justifications, risk_details
from scanner.risk import enrich_finding
from scanner.models import CryptoFinding, Evidence


def description(name, **parameters):
    finding = enrich_finding(CryptoFinding(
        algorithm_name=name, source_type="cloud-posture", observation="configured",
        evidence=[Evidence(file_path="cloud.json", rule_id="test")], **parameters))
    return next(e.risk_reasoning for e in finding.evidence if e.rule_id == "RISK-ENGINE-ASSESSMENT")


def test_cipher_suite_justifications_explain_both_axes_and_missing_parameters():
    reasons = risk_justifications(description("ECDHE-RSA-AES128-SHA256"), "Critical", "Unknown")
    assert any("Shor" in reason for reason in reasons["Quantum"])
    assert any("RSA" in reason and "desconhecido" in reason for reason in reasons["Classical"])
    assert any("ECDHE" in reason and "desconhecido" in reason for reason in reasons["Classical"])
    assert any("CBC" in reason for reason in reasons["Classical"])
    assert all("Recomendação gerada" not in reason for values in reasons.values() for reason in values)


def test_rsa_size_and_shor_reasons_are_separate():
    reasons = risk_justifications(description("RSA", key_size=2048), "Critical", "Safe")
    assert "Shor" in reasons["Quantum"][0]
    assert "2048" in reasons["Classical"][0]
    assert "Shor" not in reasons["Classical"][0]


def test_network_context_selects_missing_key_reason_for_classical_unknown():
    reasons = risk_justifications(
        "This public-key primitive is vulnerable to Shor's algorithm. "
        "A missing key or group size prevents a complete classical assessment.", "Critical", "Unknown")
    assert "Shor" in reasons["Quantum"][0]
    assert "missing" in reasons["Classical"][0]


def test_missing_reason_does_not_invent_a_justification():
    reasons = risk_justifications("unknown", "Safe", "Critical")
    assert reasons["Quantum"] == reasons["Classical"] == ["No justification recorded; inspect the evidence."]


def test_unknown_suite_retains_known_cbc_concern_and_missing_public_key_parameters():
    details = risk_details(description("ECDHE-RSA-AES128-SHA256"), "Critical", "Unknown")
    assert any("RSA" in reason for reason in details["Classical"]["missing"])
    assert any("ECDHE" in reason for reason in details["Classical"]["missing"])
    assert any("CBC" in reason for reason in details["Classical"]["known_concerns"])
    assert "quantum vulnerability" in details["Quantum"]["criterion"]


def test_presentation_preserves_external_tiers_and_does_not_reassess():
    recorded = "Unknown configuration; further review required."
    details = risk_details(recorded, "Safe", "Unknown")
    assert "Meets the quantum criteria" in details["Quantum"]["criterion"]
    assert details["Quantum"]["reasons"]


def test_signature_summary_keeps_public_key_reason_instead_of_only_hash():
    reasons = risk_justifications(description("SHA256withRSA", crypto_function="sign"), "Critical", "Unknown")
    assert any("RSA" in reason and "Shor" in reason for reason in reasons["Quantum"])
    assert any("RSA" in reason and "desconhecido" in reason for reason in reasons["Classical"])


def test_signature_missing_parameters_are_explicit_and_separate_from_hash():
    details = risk_details(description("SHA256withRSA", crypto_function="sign"), "Critical", "Unknown",
                           algorithm="SHA256withRSA")
    assert "RSA" in details["Quantum"]["criterion"]
    assert any("Shor" in reason for reason in details["Quantum"]["reasons"])
    assert details["Classical"]["missing"] == ["RSA signing-key size."]
    assert "not the RSA signing-key parameters" in details["Classical"]["reasons"][0]


def test_ecdsa_signature_does_not_assume_rsa_key_parameters():
    name = "ECDSA_WITH_SHA256"
    details = risk_details(description(name, crypto_function="sign"), "Critical", "Unknown", algorithm=name)
    assert details["Classical"]["missing"] == ["ECDSA signing-key curve and size."]
    assert "ECDSA" in details["Quantum"]["criterion"]

"""TLS assessment through the real adapter, risk policy and finding models."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scanner.models import AssetType, CryptoFinding, CryptoFunction as F, QuantumRiskLevel as Q
from scanner.network_scanner.analyser.tls_analyzer import analyze_tls


PATH = Path("captured.pcap")


def hello(**changes):
    return {
        "packet_number": 7, "stream_id": "2", "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.2", "source_port": "50123",
        "destination_port": "443", "handshake_type": "Client Hello",
        "tls_version": "TLS 1.3", "supported_versions": ["TLS 1.3"],
        "cipher_suites": [], "selected_cipher": None, "supported_groups": [],
        "key_share_groups": [], "selected_group": None, "signature_algorithms": [],
        "hello_retry_request": False, **changes,
    }


def algorithms(findings):
    return [finding for finding in findings if finding.asset_type == AssetType.ALGORITHM]


def test_empty_input_has_no_tls_findings():
    assert analyze_tls([], PATH) == []


def test_mixed_client_proposals_remain_advertised_with_separate_primitive_risks():
    findings = analyze_tls([hello(
        supported_versions=["TLS 1.3", "TLS 1.2"], cipher_suites=["0x1302", "0xc02f"],
    )], PATH)
    assert all(finding.observation == "advertised" for finding in findings)
    aes = [finding for finding in algorithms(findings) if finding.algorithm_name == "AES"]
    assert {(finding.key_size, finding.quantum_risk, finding.classical_risk) for finding in aes} == {
        (128, Q.MEDIUM, Q.SAFE), (256, Q.SAFE, Q.SAFE),
    }
    assert {finding.algorithm_name for finding in algorithms(findings)}.issuperset({"ECDHE", "RSA"})
    assert all("mapping_status" not in json.loads(finding.evidence[0].matched_snippet) for finding in aes)
    assert all(finding.evidence[0].risk_reasoning and finding.recommendation for finding in findings)


def test_server_selection_uses_only_selected_cipher_and_hybrid_group():
    findings = analyze_tls([hello(
        handshake_type="Server Hello", cipher_suites=["0x1301", "0x1302"],
        selected_cipher="0x1302", supported_groups=["29"], key_share_groups=["29"],
        selected_group="4588", signature_algorithms=["0x0804"],
    )], PATH)
    assert all(finding.observation == "negotiated" for finding in findings)
    names = {finding.algorithm_name for finding in algorithms(findings)}
    assert names == {"AES", "SHA-384", "HKDF-SHA-384", "X25519MLKEM768"}
    [aes] = [finding for finding in findings if finding.algorithm_name == "AES"]
    assert aes.key_size == 256 and aes.mode == "GCM"
    [hybrid] = [finding for finding in findings if finding.algorithm_name == "X25519MLKEM768"]
    assert hybrid.key_size is None
    assert (hybrid.quantum_risk, hybrid.classical_risk) == (Q.SAFE, Q.SAFE)
    [version] = [finding for finding in findings if finding.asset_type == AssetType.PROTOCOL]
    assert (version.quantum_risk, version.classical_risk) == (Q.UNKNOWN, Q.UNKNOWN)


@pytest.mark.parametrize("version,cipher", [
    ("TLS 1.2", "0x1302"), ("TLS 1.3", "0xc02f"),
    ("TLS 1.1", "0x009d"), ("TLS 1.0", "0xc023"), ("SSL 3.0", "0xcca8"),
])
def test_incompatible_server_cipher_preserves_unknown_risk_and_mapping_evidence(version, cipher):
    findings = analyze_tls([hello(
        handshake_type="Server Hello", tls_version=version, selected_cipher=cipher,
    )], PATH)
    [finding] = algorithms(findings)
    assert finding.algorithm_name == f"TLS-CIPHER-{cipher}"
    assert finding.crypto_function == F.UNKNOWN
    assert (finding.quantum_risk, finding.classical_risk) == (Q.UNKNOWN, Q.UNKNOWN)
    assert finding.observation == "negotiated"
    context = json.loads(finding.evidence[0].matched_snippet)
    assert context["cipher_suite"] == cipher
    assert context["mapping_status"] == "incompatible-version"
    assert finding.evidence[0].packet_number == 7


@pytest.mark.parametrize("handshake,observation", [
    ("Client Hello", "advertised"), ("Server Hello", "negotiated"),
])
def test_ssl3_evidence_names_its_mac_without_claiming_tls_hmac_security(handshake, observation):
    findings = analyze_tls([hello(
        handshake_type=handshake, tls_version="SSL 3.0", supported_versions=["SSL 3.0"],
        cipher_suites=["0x000a"], selected_cipher="0x000a",
    )], PATH)
    [mac] = [finding for finding in findings if finding.crypto_function == F.MAC]
    assert mac.algorithm_name == "SSL3-MAC-SHA-1"
    assert mac.observation == observation
    assert (mac.quantum_risk, mac.classical_risk) == (Q.UNKNOWN, Q.UNKNOWN)
    assert json.loads(mac.evidence[0].matched_snippet)["cipher_suite"] == "0x000a"
    assert mac.evidence[0].packet_number == 7
    assert not any(finding.algorithm_name.startswith("HMAC-") for finding in findings)
    [protocol] = [finding for finding in findings if finding.asset_type == AssetType.PROTOCOL]
    assert protocol.classical_risk == Q.CRITICAL


def test_unknown_identifiers_are_preserved_without_guessing_cryptography():
    findings = analyze_tls([hello(
        cipher_suites=["0xfefe"], supported_groups=["0xfdfd"], signature_algorithms=["0xfcfc"],
    )], PATH)
    unknowns = algorithms(findings)
    assert {finding.algorithm_name for finding in unknowns} == {
        "TLS-CIPHER-0xfefe", "TLS-GROUP-0xfdfd", "TLS-SIGNATURE-0xfcfc",
    }
    assert all(finding.key_size is None and finding.observation == "advertised" for finding in unknowns)
    assert all((finding.quantum_risk, finding.classical_risk) == (Q.UNKNOWN, Q.UNKNOWN)
               for finding in unknowns)


def test_retry_and_non_hello_records_do_not_create_assessed_selections():
    assert analyze_tls([
        hello(handshake_type="Server Hello", hello_retry_request=True,
              selected_cipher="0x1302", selected_group="4588"),
        hello(handshake_type="Certificate", cipher_suites=["0x1302"]),
    ], PATH) == []


@pytest.mark.parametrize("version", ["SSL 3.0", "TLS 1.0", "TLS 1.1"])
@pytest.mark.parametrize("handshake,observation", [("Client Hello", "advertised"), ("Server Hello", "negotiated")])
def test_legacy_protocol_is_classically_critical_without_asserting_quantum_security(version, handshake, observation):
    [finding] = analyze_tls([hello(
        handshake_type=handshake, tls_version=version, supported_versions=[version],
    )], PATH)
    assert finding.asset_type == AssetType.PROTOCOL and finding.protocol == version
    assert finding.observation == observation
    assert (finding.quantum_risk, finding.classical_risk) == (Q.UNKNOWN, Q.CRITICAL)
    assert version in finding.evidence[0].risk_reasoning
    assert "Disable" in finding.recommendation


@pytest.mark.parametrize("version", ["TLS 1.2", "TLS 1.3", "0x0500"])
def test_protocol_version_alone_does_not_prove_session_security(version):
    [finding] = analyze_tls([hello(tls_version=version, supported_versions=[version])], PATH)
    assert finding.protocol == version
    assert (finding.quantum_risk, finding.classical_risk) == (Q.UNKNOWN, Q.UNKNOWN)
    assert "alone does not establish" in finding.evidence[0].risk_reasoning
    assert finding.recommendation


def test_signature_capabilities_are_advertised_and_do_not_invent_rsa_size():
    findings = analyze_tls([hello(signature_algorithms=["0x0804"])], PATH)
    [rsa] = [finding for finding in algorithms(findings) if finding.algorithm_name == "RSA"]
    assert rsa.observation == "advertised" and rsa.crypto_function == F.SIGN
    assert rsa.key_size is None and rsa.padding == "PSS"
    assert (rsa.quantum_risk, rsa.classical_risk) == (Q.CRITICAL, Q.UNKNOWN)
    assert "missing key or group size" in rsa.evidence[0].risk_reasoning.lower()
    assert not any(finding.observation == "negotiated" for finding in findings)


def test_static_rsa_server_suite_is_quantum_critical_with_unknown_key_size():
    findings = analyze_tls([hello(
        handshake_type="Server Hello", tls_version="TLS 1.2", selected_cipher="0x002f",
    )], PATH)
    [rsa] = [finding for finding in algorithms(findings) if finding.algorithm_name == "RSA"]
    assert rsa.crypto_function == F.KEY_EXCHANGE and rsa.key_size is None
    assert (rsa.quantum_risk, rsa.classical_risk) == (Q.CRITICAL, Q.UNKNOWN)
    assert "provides no forward secrecy" in rsa.evidence[0].risk_reasoning
    assert not any(finding.algorithm_name == "SHA-1" and finding.crypto_function == F.DIGEST
                   for finding in findings)


def test_grease_and_signaling_markers_are_excluded_from_primitive_assessment():
    findings = analyze_tls([hello(
        cipher_suites=["0x0a0a", "0x00ff", "0x5600"], supported_groups=["0x1a1a"],
        key_share_groups=["0x2a2a"], signature_algorithms=["0x3a3a"],
    )], PATH)
    assert algorithms(findings) == []


def test_assessed_findings_preserve_json_evidence_and_metadata_without_exposing_secrets():
    entries = [hello(
        cipher_suites=["0x1302"], server_name="service.example", http_host="user:SECRET@example.test",
        **{"tcp.payload": "SECRET", "private_key": "SECRET", "http_uri": "/?token=SECRET"},
    )]
    before = copy.deepcopy(entries)
    findings = analyze_tls(entries, PATH)
    assert entries == before
    for finding in findings:
        evidence = finding.evidence[0]
        assert evidence.file_path == str(PATH) and evidence.packet_number == 7
        context = json.loads(evidence.matched_snippet)
        assert context["source_ip"] == "192.0.2.1" and context["destination_ip"] == "198.51.100.2"
        assert context["stream_id"] == "2" and context["server_name"] == "service.example"
        assert context["http_host"] == "example.test"
        assert not {"tcp.payload", "private_key", "http_uri"}.intersection(context)
        payload = finding.to_dict()
        assert "SECRET" not in json.dumps(payload)
        assert CryptoFinding.model_validate(json.loads(json.dumps(payload))) == finding

"""Testes unitarios do mapper sem TShark, capturas ou acesso a rede."""

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.models import AssetType, CryptoFinding, CryptoFunction as F, QuantumRiskLevel as Q
from scanner.network_scanner import algorithm_mapper as mapper


@pytest.mark.parametrize("raw,expected", [
    (0, 0), (65535, 65535), (4866, 4866), ("4866", 4866),
    ("0x1302", 4866), (" 0X1302 ", 4866), ("C02F", 49199),
    ("0013", 13), ("1302", 1302), ("0xffff", 65535),
    (None, None), (True, None), (False, None), (-1, None),
    (65536, None), ("0x10000", None), ("", None), ("  ", None),
    ("0x", None), ("0xZZ", None), ("-1", None), ("+1", None),
    ("1_302", None), ("1.9", None), (1.9, None), ([], None),
])
def test_identifier_formats_and_boundaries(raw, expected):
    """Valida bases numericas, limites de 16 bits e formatos invalidos."""
    assert mapper.parse_identifier(raw) == expected


def test_grease_exact_set_over_all_16_bit_identifiers():
    """Verifica os 65536 identificadores e reconhece exatamente os 16 valores GREASE."""
    expected = {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
        0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }
    assert {value for value in range(65536) if mapper.is_grease(value)} == expected
    assert mapper.is_grease(None) is False


@pytest.mark.parametrize("raw,expected", [
    (29, "0x001d"), ("4866", "0x1302"), ("0X1302", "0x1302"),
    (65535, "0xffff"), ("future-id", "future-id"), (-1, "-1"),
])
def test_identifier_labels_preserve_unknown_values(raw, expected):
    """Uniformiza identificadores validos e preserva entradas desconhecidas."""
    assert mapper.identifier_label(raw) == expected


@pytest.mark.parametrize("identifier,cipher,bits,mode,digest", [
    (0x1301, "AES", 128, "GCM", "SHA-256"),
    (0x1302, "AES", 256, "GCM", "SHA-384"),
    (0x1303, "ChaCha20-Poly1305", 256, None, "SHA-256"),
    (0x1304, "AES", 128, "CCM", "SHA-256"),
    (0x1305, "AES", 128, "CCM_8", "SHA-256"),
])
def test_tls13_exact_primitives_without_invented_authentication(identifier, cipher, bits, mode, digest):
    """Verifica todas as suites TLS 1.3 sem inferir assinatura ou troca de chaves."""
    suite = mapper.CIPHER_SUITES[identifier]
    assert suite.key_exchange is None and suite.authentication is None
    assert mapper.cipher_primitives(suite, "TLS 1.3") == [
        mapper.Primitive(cipher, F.ENCRYPT, bits, mode),
        mapper.Primitive(digest, F.DIGEST),
        mapper.Primitive(f"HKDF-{digest}", F.KDF),
    ]


@pytest.mark.parametrize("identifier,expected", [
    (0x002F, [mapper.Primitive("RSA", F.KEY_EXCHANGE),
              mapper.Primitive("AES", F.ENCRYPT, 128, "CBC"),
              mapper.Primitive("SHA-1", F.DIGEST),
              mapper.Primitive("HMAC-SHA-1", F.MAC),
              mapper.Primitive("TLS-PRF-SHA-256", F.KDF)]),
    (0x009F, [mapper.Primitive("DHE", F.KEY_EXCHANGE),
              mapper.Primitive("RSA", F.SIGN),
              mapper.Primitive("AES", F.ENCRYPT, 256, "GCM"),
              mapper.Primitive("SHA-384", F.DIGEST),
              mapper.Primitive("TLS-PRF-SHA-384", F.KDF)]),
    (0xC02B, [mapper.Primitive("ECDHE", F.KEY_EXCHANGE),
              mapper.Primitive("ECDSA", F.SIGN),
              mapper.Primitive("AES", F.ENCRYPT, 128, "GCM"),
              mapper.Primitive("SHA-256", F.DIGEST),
              mapper.Primitive("TLS-PRF-SHA-256", F.KDF)]),
    (0x0004, [mapper.Primitive("RSA", F.KEY_EXCHANGE),
              mapper.Primitive("RC4", F.ENCRYPT, 128),
              mapper.Primitive("MD5", F.DIGEST),
              mapper.Primitive("HMAC-MD5", F.MAC),
              mapper.Primitive("TLS-PRF-SHA-256", F.KDF)]),
    (0x0002, [mapper.Primitive("RSA", F.KEY_EXCHANGE),
              mapper.Primitive("NULL", F.ENCRYPT),
              mapper.Primitive("SHA-1", F.DIGEST),
              mapper.Primitive("HMAC-SHA-1", F.MAC),
              mapper.Primitive("TLS-PRF-SHA-256", F.KDF)]),
])
def test_tls12_primitive_functions_and_parameters(identifier, expected):
    """Verifica combinacoes RSA, DHE, ECDHE, CBC e AEAD com a PRF correta."""
    assert mapper.cipher_primitives(mapper.CIPHER_SUITES[identifier], "TLS 1.2") == expected


@pytest.mark.parametrize("version,expected", [
    ("TLS 1.0", [mapper.Primitive("TLS-PRF-MD5-SHA-1", F.KDF)]),
    ("TLS 1.1", [mapper.Primitive("TLS-PRF-MD5-SHA-1", F.KDF)]),
    (None, []), ("future-version", []),
])
def test_prf_depends_on_known_protocol_version(version, expected):
    """Escolhe a PRF pela versao e nao inventa uma KDF para versoes desconhecidas."""
    primitives = mapper.cipher_primitives(mapper.CIPHER_SUITES[0x002F], version)
    assert [p for p in primitives if p.crypto_function == F.KDF] == expected


@pytest.mark.parametrize("identifier,name,bits", [
    (23, "ECDHE-secp256r1", 256), (24, "ECDHE-secp384r1", 384),
    (25, "ECDHE-secp521r1", 521), (29, "ECDHE-X25519", 255),
    (30, "ECDHE-X448", 448), (256, "DHE-ffdhe2048", 2048),
    (257, "DHE-ffdhe3072", 3072), (258, "DHE-ffdhe4096", 4096),
    (259, "DHE-ffdhe6144", 6144), (260, "DHE-ffdhe8192", 8192),
    (512, "ML-KEM-512", None), (513, "ML-KEM-768", None),
    (514, "ML-KEM-1024", None), (4587, "SecP256r1MLKEM768", None),
    (4588, "X25519MLKEM768", None), (4589, "SecP384r1MLKEM1024", None),
    (25497, "X25519Kyber768Draft00", None),
    (25498, "SecP256r1Kyber768Draft00", None),
])
def test_group_identifiers_preserve_hybrids_and_known_sizes(identifier, name, bits):
    """Verifica os grupos conhecidos sem confundir parametros KEM com tamanho de chave."""
    assert mapper.GROUPS[identifier] == mapper.Primitive(name, F.KEY_EXCHANGE, bits)


@pytest.mark.parametrize("identifier,name,padding,digest", [
    (0x0201, "RSA", "PKCS1v15", "SHA-1"),
    (0x0401, "RSA", "PKCS1v15", "SHA-256"),
    (0x0501, "RSA", "PKCS1v15", "SHA-384"),
    (0x0601, "RSA", "PKCS1v15", "SHA-512"),
    (0x0202, "DSA", None, "SHA-1"), (0x0402, "DSA", None, "SHA-256"),
    (0x0502, "DSA", None, "SHA-384"), (0x0602, "DSA", None, "SHA-512"),
    (0x0203, "ECDSA", None, "SHA-1"), (0x0403, "ECDSA", None, "SHA-256"),
    (0x0503, "ECDSA", None, "SHA-384"), (0x0603, "ECDSA", None, "SHA-512"),
    (0x0804, "RSA", "PSS", "SHA-256"), (0x0805, "RSA", "PSS", "SHA-384"),
    (0x0806, "RSA", "PSS", "SHA-512"), (0x0809, "RSA", "PSS", "SHA-256"),
    (0x080A, "RSA", "PSS", "SHA-384"), (0x080B, "RSA", "PSS", "SHA-512"),
])
def test_signature_components_do_not_invent_key_size(identifier, name, padding, digest):
    """Verifica assinatura, padding e hash sem inferir tamanho RSA a partir do hash."""
    assert mapper.SIGNATURE_SCHEMES[identifier] == (
        mapper.Primitive(name, F.SIGN, padding=padding),
        mapper.Primitive(digest, F.DIGEST),
    )


@pytest.mark.parametrize("identifier,name,bits", [(0x0807, "Ed25519", 255), (0x0808, "Ed448", 448)])
def test_eddsa_signature_is_one_primitive(identifier, name, bits):
    """Preserva EdDSA como uma primitiva sem acrescentar um hash independente."""
    assert mapper.SIGNATURE_SCHEMES[identifier] == (mapper.Primitive(name, F.SIGN, bits),)


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
    ("HMAC-SHA-256", None, None, F.MAC, Q.SAFE, Q.SAFE),
    ("HKDF_SHA-384", None, None, F.KDF, Q.SAFE, Q.SAFE),
    ("TLS-PRF-SHA-256", None, None, F.KDF, Q.SAFE, Q.SAFE),
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
    actual_quantum, actual_classical, reason, recommendation = mapper.assess_primitive(name, bits, mode, function)
    assert (actual_quantum, actual_classical) == (quantum, classical)
    assert reason.strip() and recommendation.strip()


@pytest.mark.parametrize("raw,expected", [
    (1, 1), (73, 73), ("73", 73), (" 73 ", 73),
    (None, None), (True, None), (False, None), (0, None), (-1, None),
    (1.9, None), (1.0, None), ("1.9", None), ("1_000", None), ("bad", None),
])
def test_evidence_packet_number_is_positive_integer(raw, expected):
    """Rejeita numeros fracionarios e invalidos sem apontar para outro pacote."""
    evidence = mapper.network_evidence(Path("sample.pcap"), {"packet_number": raw}, "CHECK")
    assert evidence.packet_number == expected
    assert evidence.file_path == "sample.pcap" and evidence.rule_id == "CHECK"


def test_evidence_json_preserves_context_without_mutating_input():
    """Serializa os detalhes e a justificacao sem modificar a observacao original."""
    entry = {"packet_number": 7, "stream_id": "2", "nested": {"groups": [29]}, "path": Path("context")}
    before = copy.deepcopy(entry)
    evidence = mapper.network_evidence(Path("sample.pcap"), entry, "CHECK", reasoning="Policy explanation")
    assert json.loads(evidence.matched_snippet) == {
        "packet_number": 7, "stream_id": "2", "nested": {"groups": [29]}, "path": "context",
    }
    assert evidence.risk_reasoning == "Policy explanation"
    assert entry == before


def test_explicit_evidence_snippet_is_preserved():
    """Mantem um snippet explicito em vez de o substituir pelo dicionario completo."""
    evidence = mapper.network_evidence(Path("sample.pcap"), {"matched_snippet": "Selected AES"}, "CHECK")
    assert evidence.matched_snippet == "Selected AES"


@pytest.mark.parametrize("observation", ["declared", "configured", "advertised", "negotiated", "observed"])
def test_finding_model_serialization_and_assessment(observation):
    """Cria um model valido e preserva o tipo de observacao ao aplicar a politica de risco."""
    finding = mapper.make_finding(
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


def test_risk_override_and_optional_finding_fields():
    """Respeita uma avaliacao explicita e preserva campos opcionais desconhecidos."""
    finding = mapper.make_finding(
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
        mapper.make_finding(Path("sample.pcap"), {}, **kwargs)

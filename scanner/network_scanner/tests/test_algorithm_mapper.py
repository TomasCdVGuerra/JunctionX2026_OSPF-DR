"""Testes unitarios do mapper sem TShark, capturas ou acesso a rede."""

import copy
import json
from pathlib import Path

import pytest

from scanner.models import CryptoFunction as F
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


@pytest.mark.parametrize("identifier", [0x1301, 0x1302, 0x1303, 0x1304, 0x1305])
@pytest.mark.parametrize("version", ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"])
def test_tls13_suite_rejects_explicit_older_version(identifier, version):
    """Rejeita suites TLS 1.3 associadas explicitamente a uma versao anterior."""
    with pytest.raises(mapper.CipherSuiteVersionError, match="incompatible"):
        mapper.cipher_primitives(mapper.CIPHER_SUITES[identifier], version)


@pytest.mark.parametrize("identifier", [0x002F, 0x009F, 0xC02F, 0xCCA8])
def test_older_suite_rejects_tls13_version(identifier):
    """Impede apresentar uma suite anterior como uma escolha valida em TLS 1.3."""
    with pytest.raises(mapper.CipherSuiteVersionError, match="TLS 1.3"):
        mapper.cipher_primitives(mapper.CIPHER_SUITES[identifier], "TLS 1.3")


@pytest.mark.parametrize("version", [None, "future-version"])
def test_unknown_version_does_not_invent_incompatibility(version):
    """Preserva a traducao conhecida sem afirmar incompatibilidade com versao desconhecida."""
    primitives = mapper.cipher_primitives(mapper.CIPHER_SUITES[0x1302], version)
    assert [p.algorithm_name for p in primitives] == ["AES", "SHA-384", "HKDF-SHA-384"]


@pytest.mark.parametrize("identifier", [-1, 65536, 0x10A0A, True, False, "0x0a0a", 1.9])
def test_grease_rejects_out_of_range_and_invalid_types(identifier):
    """Rejeita valores fora de 16 bits e tipos invalidos sem classificar como GREASE."""
    assert mapper.is_grease(identifier) is False


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
    """Preserva contexto permitido e exclui campos arbitrarios sem modificar a entrada."""
    entry = {"packet_number": 7, "stream_id": "2", "nested": {"password": "SECRET"},
             "password": "SECRET", "tcp.payload": "SECRET", "http_host": "user:SECRET@example.test"}
    before = copy.deepcopy(entry)
    evidence = mapper.network_evidence(Path("sample.pcap"), entry, "CHECK", reasoning="Policy explanation")
    assert json.loads(evidence.matched_snippet) == {
        "packet_number": 7, "stream_id": "2", "http_host": "example.test",
    }
    assert evidence.risk_reasoning == "Policy explanation"
    assert entry == before


@pytest.mark.parametrize("host,expected", [
    ("example.test", "example.test"), (" example.test:8080 ", "example.test:8080"),
    ("user:SECRET@example.test", "example.test"),
    ("user:SECRET@[2001:db8::1]:8080", "[2001:db8::1]:8080"),
    ("user:SECRET@", None), ("", None), ({"password": "SECRET"}, None),
])
def test_network_context_removes_http_host_credentials(host, expected):
    """Remove credenciais preservando hostname, IPv6 e porta quando disponiveis."""
    entry = {"http_host": host, "source_ip": "192.0.2.1"}
    before = copy.deepcopy(entry)
    details = mapper.network_context(entry)
    assert details.get("http_host") == expected
    assert details["source_ip"] == "192.0.2.1"
    assert "SECRET" not in json.dumps(details)
    assert entry == before


@pytest.mark.parametrize("with_context", [False, True])
def test_explicit_evidence_snippet_is_rebuilt_from_allowed_context(with_context):
    """Ignora texto arbitrario e gera evidencia apenas com o contexto permitido."""
    entry = {"matched_snippet": "password=SECRET", "password": "SECRET", "payload": "SECRET"}
    expected = {}
    if with_context:
        entry.update(packet_number="42", tls_version="TLS 1.3", cipher_suite="0x1302")
        expected = {"packet_number": 42, "tls_version": "TLS 1.3", "cipher_suite": "0x1302"}
    before = copy.deepcopy(entry)
    evidence = mapper.network_evidence(Path("sample.pcap"), entry, "CHECK")
    assert isinstance(evidence.matched_snippet, str)
    assert json.loads(evidence.matched_snippet) == expected
    assert "SECRET" not in evidence.matched_snippet
    assert entry == before

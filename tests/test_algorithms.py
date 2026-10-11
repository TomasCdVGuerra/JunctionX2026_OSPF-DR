import pytest

from scanner.algorithms import normalise, parse_signature_algorithm, parse_tls13_cipher_suite, parse_legacy_cipher_suite

import json
from pathlib import Path

@pytest.mark.parametrize(
    "raw_name, expected",
    [
        (" rsa ", "RSA"),
        ("ECC", "EC"),
        ("aes", "AES"),
        ("sha256", "SHA-256"),
        ("SHA_256", "SHA-256"),
        ("SHA-384", "SHA-384"),
        ("ED25519", "Ed25519"),
        (None, "unknown"),
        ("   ", "unknown"),
        ("UNKNOWN", "unknown"),
        ("FutureCipher", "FutureCipher"),
        ("SHA256WITHRSA", "SHA256WITHRSA"),
        (
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ),
        (
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_256_GCM_SHA384",
        ),
    ],
)
def test_normalise_names(raw_name, expected):
    assert normalise(raw_name) == expected


@pytest.mark.parametrize("raw_name", [42, [], {}])
def test_normalise_rejects_invalid_types(raw_name):
    with pytest.raises(ValueError, match="string"):
        normalise(raw_name)


@pytest.mark.parametrize(
    "raw_name, expected",
    [
        ("SHA1WITHRSA", ("RSA", "SHA-1")),
        ("SHA256WITHRSA", ("RSA", "SHA-256")),
        ("ECDSA_WITH_SHA256", ("ECDSA", "SHA-256")),
        ("ECDSA_WITH_SHA384", ("ECDSA", "SHA-384")),
        (" sha256withrsa ", ("RSA", "SHA-256")),
        ("SHA384withECDSA", ("ECDSA", "SHA-384")),
        (None, None),
        ("RSA", None),
        ("FutureSignature", None),
        ("SHA256CUSTOMRSA", None),
        ("ECDHE-RSA-AES128-GCM-SHA256", None),
    ],
)
def test_parse_signature_algorithm(raw_name, expected):
    assert parse_signature_algorithm(raw_name) == expected


@pytest.mark.parametrize("raw_name", [42, [], {}])
def test_parse_signature_algorithm_rejects_invalid_types(raw_name):
    with pytest.raises(ValueError, match="string"):
        parse_signature_algorithm(raw_name)


@pytest.mark.parametrize(
    "name, algorithm, key_size, mode, hash_algorithm",
    [
        (
            "TLS_AES_128_GCM_SHA256",
            "AES", 128, "GCM", "SHA-256",
        ),
        (
            " tls_aes_256_gcm_sha384 ",
            "AES", 256, "GCM", "SHA-384",
        ),
        (
            "TLS_CHACHA20_POLY1305_SHA256",
            "ChaCha20-Poly1305", 256, None, "SHA-256",
        ),
    ],
)
def test_parse_tls13_cipher_suite(
    name, algorithm, key_size, mode, hash_algorithm
):
    components = parse_tls13_cipher_suite(name)

    assert components is not None
    assert components.symmetric_algorithm == algorithm
    assert components.symmetric_key_size == key_size
    assert components.mode == mode
    assert components.hash_algorithm == hash_algorithm
    assert components.hash_role == "hkdf"
    assert components.tls_version == "TLSv1.3"

    assert components.key_exchange is None
    assert components.authentication is None


@pytest.mark.parametrize(
    "name",
    [
        None,
        "RSA",
        "TLS_AES_256_GCM_SHA512",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ],
)
def test_unrecognised_tls13_suite(name):
    assert parse_tls13_cipher_suite(name) is None


@pytest.mark.parametrize("name", [42, [], {}])
def test_tls13_suite_rejects_invalid_types(name):
    with pytest.raises(ValueError, match="string"):
        parse_tls13_cipher_suite(name)


@pytest.mark.parametrize(
    "name, exchange, auth, bits, mode, digest, role",
    [
        (
            " ecdhe-rsa-aes128-gcm-sha256 ",
            "ECDHE", "RSA", 128, "GCM", "SHA-256", "prf",
        ),
        (
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE", "ECDSA", 256, "GCM", "SHA-384", "prf",
        ),
        (
            "ECDHE-RSA-AES128-SHA",
            "ECDHE", "RSA", 128, "CBC", "SHA-1", "mac",
        ),
        (
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE", "ECDSA", 256, "CBC", "SHA-384", "mac/prf",
        ),
        (
            "AES128-SHA256",
            "RSA", "RSA", 128, "CBC", "SHA-256", "mac/prf",
        ),
        (
            "AES256-SHA256",
            "RSA", "RSA", 256, "CBC", "SHA-256", "mac/prf",
        ),
    ],
)
def test_parse_legacy_cipher_suite(
    name, exchange, auth, bits, mode, digest, role
):
    components = parse_legacy_cipher_suite(name)

    assert components is not None
    assert components.symmetric_algorithm == "AES"
    assert components.symmetric_key_size == bits
    assert components.mode == mode
    assert components.hash_algorithm == digest
    assert components.hash_role == role
    assert components.key_exchange == exchange
    assert components.authentication == auth
    assert components.tls_version is None


@pytest.mark.parametrize(
    "name",
    [
        None,
        "ECDHE-RSA-AES256-SHA256",
        "AES256-SHA384",
        "TLS_AES_256_GCM_SHA384",
    ],
)
def test_unrecognised_legacy_suite(name):
    assert parse_legacy_cipher_suite(name) is None


@pytest.mark.parametrize("name", [42, [], {}])
def test_legacy_suite_rejects_invalid_types(name):
    with pytest.raises(ValueError, match="string"):
        parse_legacy_cipher_suite(name)


def test_cipher_parsers_cover_elb_policy_map():
    policy_file = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "elb_policies.json"
    )
    data = json.loads(policy_file.read_text(encoding="utf-8"))

    names = {
        cipher
        for policy in data["policies"].values()
        for cipher in policy["ciphers"]
    }

    assert len(names) == 21

    for name in names:
        components = (
            parse_tls13_cipher_suite(name)
            or parse_legacy_cipher_suite(name)
        )

        assert components is not None, f"Suite não interpretado: {name}"
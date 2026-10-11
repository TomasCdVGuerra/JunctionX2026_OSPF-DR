"""Normalização de nomes criptográficos para o Risk Engine."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PQCAlgorithm:
    """Parâmetro normalizado; o número no nome não é key_size em bits."""
    family: str
    purpose: str
    standard: str
    source_url: str


PQC_ALGORITHMS: dict[str, PQCAlgorithm] = {}
for _parameter in ("512", "768", "1024"):
    PQC_ALGORITHMS[f"ML-KEM-{_parameter}"] = PQCAlgorithm(
        "ML-KEM", "key-establishment", "FIPS 203",
        "https://csrc.nist.gov/pubs/fips/203/final",
    )
for _parameter in ("44", "65", "87"):
    PQC_ALGORITHMS[f"ML-DSA-{_parameter}"] = PQCAlgorithm(
        "ML-DSA", "signature", "FIPS 204",
        "https://csrc.nist.gov/pubs/fips/204/final",
    )
for _hash in ("SHA2", "SHAKE"):
    for _parameter in ("128s", "128f", "192s", "192f", "256s", "256f"):
        PQC_ALGORITHMS[f"SLH-DSA-{_hash}-{_parameter}"] = PQCAlgorithm(
            "SLH-DSA", "signature", "FIPS 205",
            "https://csrc.nist.gov/pubs/fips/205/final",
        )

@dataclass(frozen=True)
class CipherSuiteComponents:
    """Componentes conhecidos de um cipher suite; não de uma sessão."""
    symmetric_algorithm: str
    symmetric_key_size: int
    mode: str | None
    hash_algorithm: str
    hash_role: str
    key_exchange: str | None = None
    authentication: str | None = None
    tls_version: str | None = None

ALGORITHM_ALIASES: dict[str, str] = {
    "RSA": "RSA",
    "EC": "EC",
    "ECC": "EC",
    "ECDSA": "ECDSA",
    "ECDH": "ECDH",
    "DSA": "DSA",
    "DH": "DH",
    "ED25519": "Ed25519",
    "X25519": "X25519",
    "CURVE25519": "Curve25519",
    "AES": "AES",
    "SM4": "SM4",
    "DES": "DES",
    "3DES": "3DES",
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "ECDHE": "ECDHE",
    "CHACHA20": "ChaCha20",
    "CHACHA20POLY1305": "ChaCha20-Poly1305",
}
ALGORITHM_ALIASES.update({
    name.upper().replace("-", ""): name for name in PQC_ALGORITHMS
})


def parse_pqc_algorithm(raw_name: str | None) -> PQCAlgorithm | None:
    """Aceita apenas parâmetros completos conhecidos; não converte drafts."""
    return PQC_ALGORITHMS.get(normalise(raw_name))

SIGNATURE_ALGORITHMS: dict[str, tuple[str, str]] = {
    "SHA1WITHRSA": ("RSA", "SHA-1"),
    "SHA256WITHRSA": ("RSA", "SHA-256"),
    "SHA384WITHRSA": ("RSA", "SHA-384"),
    "SHA512WITHRSA": ("RSA", "SHA-512"),
    "ECDSAWITHSHA256": ("ECDSA", "SHA-256"),
    "ECDSAWITHSHA384": ("ECDSA", "SHA-384"),
    "ECDSAWITHSHA512": ("ECDSA", "SHA-512"),
    "SHA256WITHECDSA": ("ECDSA", "SHA-256"),
    "SHA384WITHECDSA": ("ECDSA", "SHA-384"),
    "SHA512WITHECDSA": ("ECDSA", "SHA-512"),
}


TLS13_CIPHER_SUITES: dict[str, CipherSuiteComponents] = {
    "TLS_AES_128_GCM_SHA256": CipherSuiteComponents(
        symmetric_algorithm="AES",
        symmetric_key_size=128,
        mode="GCM",
        hash_algorithm="SHA-256",
        hash_role="hkdf",
        tls_version="TLSv1.3",
    ),
    "TLS_AES_256_GCM_SHA384": CipherSuiteComponents(
        symmetric_algorithm="AES",
        symmetric_key_size=256,
        mode="GCM",
        hash_algorithm="SHA-384",
        hash_role="hkdf",
        tls_version="TLSv1.3",
    ),
    "TLS_CHACHA20_POLY1305_SHA256": CipherSuiteComponents(
        symmetric_algorithm="ChaCha20-Poly1305",
        symmetric_key_size=256,
        mode=None,
        hash_algorithm="SHA-256",
        hash_role="hkdf",
        tls_version="TLSv1.3",
    ),
}


# Tamanho simétrico, modo, hash e função do hash.
COMMON_LEGACY_AES: dict[str, tuple[int, str, str, str]] = {
    "AES128-GCM-SHA256": (128, "GCM", "SHA-256", "prf"),
    "AES256-GCM-SHA384": (256, "GCM", "SHA-384", "prf"),
    "AES128-SHA256": (128, "CBC", "SHA-256", "mac/prf"),
    "AES128-SHA": (128, "CBC", "SHA-1", "mac"),
    "AES256-SHA": (256, "CBC", "SHA-1", "mac"),
}

ECDHE_LEGACY_AES = {
    **COMMON_LEGACY_AES,
    "AES256-SHA384": (256, "CBC", "SHA-384", "mac/prf"),
}

RSA_LEGACY_AES = {
    **COMMON_LEGACY_AES,
    "AES256-SHA256": (256, "CBC", "SHA-256", "mac/prf"),
}


def normalise(raw_name: str | None) -> str:
    """Uniformiza nomes conhecidos e preserva nomes não reconhecidos."""
    if raw_name is None:
        return "unknown"

    if not isinstance(raw_name, str):
        raise ValueError("O nome do algoritmo deve ser uma string")

    name = raw_name.strip()

    if not name:
        return "unknown"

    lookup_name = name.upper().replace("-", "").replace("_", "")

    if lookup_name == "UNKNOWN":
        return "unknown"

    return ALGORITHM_ALIASES.get(lookup_name, name)


@dataclass(frozen=True)
class PrimitiveComponents:
    family: str
    key_size: int | None = None
    mode: str | None = None


def parse_primitive_name(raw_name: str | None) -> PrimitiveComponents | None:
    """Interpreta nomes explícitos RSA/AES, sem pesquisar substrings."""
    name = normalise(raw_name).upper().replace("_", "-")
    rsa = re.fullmatch(r"RSA-([1-9][0-9]*)", name)
    if rsa:
        return PrimitiveComponents("RSA", int(rsa[1]))
    modes = r"ECB|CBC|GCM|CCM|CTR|CFB|OFB|UNKNOWN"
    aes = re.fullmatch(rf"AES-(?:([1-9][0-9]*)(?:-({modes}))?|({modes}))", name)
    if aes:
        return PrimitiveComponents(
            "AES", int(aes[1]) if aes[1] else None, aes[2] or aes[3],
        )
    return None


def parse_hash_construction(raw_name: str | None) -> tuple[str, str] | None:
    """Reconhece HMAC/PBKDF2 completos; o hash não define a segurança total."""
    lookup = normalise(raw_name).upper().replace("-", "").replace("_", "")
    for digest in ("MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"):
        suffix = digest.replace("-", "")
        if lookup == f"HMAC{suffix}":
            return "HMAC", digest
        if lookup == f"PBKDF2HMAC{suffix}":
            return "PBKDF2", digest
    return None


def parse_signature_algorithm(raw_name: str | None) -> tuple[str, str] | None:
    """Decompõe nomes de assinatura conhecidos sem adivinhar componentes."""
    name = normalise(raw_name)
    lookup_name = name.upper().replace("-", "").replace("_", "")

    return SIGNATURE_ALGORITHMS.get(lookup_name)


def parse_tls13_cipher_suite(raw_name: str | None) -> CipherSuiteComponents | None:
    """Interpreta os cipher suites TLS 1.3 conhecidos pelo catálogo."""
    name = normalise(raw_name).upper()

    return TLS13_CIPHER_SUITES.get(name)


def parse_legacy_cipher_suite(raw_name: str | None,) -> CipherSuiteComponents | None:
    """Interpreta os nomes OpenSSL anteriores ao TLS 1.3 suportados."""
    name = normalise(raw_name).upper()

    if name.startswith("ECDHE-ECDSA-"):
        suffix = name.removeprefix("ECDHE-ECDSA-")
        key_exchange = "ECDHE"
        authentication = "ECDSA"
        specifications = ECDHE_LEGACY_AES

    elif name.startswith("ECDHE-RSA-"):
        suffix = name.removeprefix("ECDHE-RSA-")
        key_exchange = "ECDHE"
        authentication = "RSA"
        specifications = ECDHE_LEGACY_AES

    else:
        suffix = name
        key_exchange = "RSA"
        authentication = "RSA"
        specifications = RSA_LEGACY_AES

    specification = specifications.get(suffix)

    if specification is None:
        return None

    key_size, mode, hash_algorithm, hash_role = specification

    return CipherSuiteComponents(
        symmetric_algorithm="AES",
        symmetric_key_size=key_size,
        mode=mode,
        hash_algorithm=hash_algorithm,
        hash_role=hash_role,
        key_exchange=key_exchange,
        authentication=authentication,
    )

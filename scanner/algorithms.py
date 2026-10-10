"""Cryptographic algorithm normalization, OID registry, and taxonomy mappings."""

from __future__ import annotations

import re

# Standard Object Identifier (OID) lookup database
OID_MAP: dict[str, str] = {
    # Post-Quantum Cryptography standards (FIPS 203, 204, 205)
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    "KYBER-512": "2.16.840.1.101.3.4.4.1",
    "KYBER-768": "2.16.840.1.101.3.4.4.2",
    "KYBER-1024": "2.16.840.1.101.3.4.4.3",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
    "DILITHIUM2": "2.16.840.1.101.3.4.3.17",
    "DILITHIUM3": "2.16.840.1.101.3.4.3.18",
    "DILITHIUM5": "2.16.840.1.101.3.4.3.19",
    "SLH-DSA": "2.16.840.1.101.3.4.3.22",
    "SPHINCS+": "2.16.840.1.101.3.4.3.22",

    # Asymmetric public key algorithms
    "RSA": "1.2.840.113549.1.1.1",
    "RSAES-OAEP": "1.2.840.113549.1.1.7",
    "RSASSA-PSS": "1.2.840.113549.1.1.10",
    "DSA": "1.2.840.10040.4.1",
    "DH": "1.2.840.113549.1.3.1",
    "DIFFIE-HELLMAN": "1.2.840.113549.1.3.1",
    "ECDSA": "1.2.840.10045.2.1",
    "ECDH": "1.3.132.1.12",
    "ED25519": "1.3.101.112",
    "ED448": "1.3.101.113",
    "X25519": "1.3.101.110",
    "X448": "1.3.101.111",

    # Elliptic curves
    "SECP256R1": "1.2.840.10045.3.1.7",
    "PRIME256V1": "1.2.840.10045.3.1.7",
    "SECP384R1": "1.3.132.0.34",
    "SECP521R1": "1.3.132.0.35",

    # Symmetric ciphers (AES modes)
    "AES-128-ECB": "2.16.840.1.101.3.4.1.1",
    "AES-128-CBC": "2.16.840.1.101.3.4.1.2",
    "AES-128-OFB": "2.16.840.1.101.3.4.1.3",
    "AES-128-CFB": "2.16.840.1.101.3.4.1.4",
    "AES-128-GCM": "2.16.840.1.101.3.4.1.6",
    "AES-192-ECB": "2.16.840.1.101.3.4.1.21",
    "AES-192-CBC": "2.16.840.1.101.3.4.1.22",
    "AES-192-GCM": "2.16.840.1.101.3.4.1.26",
    "AES-256-ECB": "2.16.840.1.101.3.4.1.41",
    "AES-256-CBC": "2.16.840.1.101.3.4.1.42",
    "AES-256-OFB": "2.16.840.1.101.3.4.1.43",
    "AES-256-CFB": "2.16.840.1.101.3.4.1.44",
    "AES-256-GCM": "2.16.840.1.101.3.4.1.46",

    # Legacy & broken ciphers
    "DES": "1.3.14.3.2.7",
    "3DES": "1.2.840.113549.3.7",
    "DES-EDE3-CBC": "1.2.840.113549.3.7",

    # Hash functions
    "MD5": "1.2.840.113549.2.5",
    "SHA-1": "1.3.14.3.2.26",
    "SHA-224": "2.16.840.1.101.3.4.2.4",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "SHA3-384": "2.16.840.1.101.3.4.2.9",
    "SHA3-512": "2.16.840.1.101.3.4.2.10",

    # Message authentication & KDF
    "HMAC-SHA256": "1.2.840.113549.2.9",
    "HMAC-SHA384": "1.2.840.113549.2.10",
    "HMAC-SHA512": "1.2.840.113549.2.11",
    "PBKDF2": "1.2.840.113549.1.5.12",
}


def normalise(raw_name: str) -> str:
    """Standardize cryptographic algorithm name into canonical presentation form."""
    if not raw_name or not raw_name.strip():
        return "unknown"

    cleaned = raw_name.strip()
    upper = cleaned.upper().replace("_", "-").replace("/", "-")

    # Composite signatures
    if "SHA1WITHRSA" in upper or "RSA-WITH-SHA1" in upper or "SHA1-RSA" in upper:
        return "SHA1withRSA"
    if "SHA256WITHRSA" in upper or "RSA-WITH-SHA256" in upper or "SHA256-RSA" in upper:
        return "SHA256withRSA"
    if "ECDSA-WITH-SHA256" in upper or "SHA256WITHECDSA" in upper:
        return "ECDSA-SHA256"

    # Post-quantum
    if "ML-KEM" in upper or "KYBER" in upper:
        for size in ("1024", "768", "512"):
            if size in upper:
                return f"ML-KEM-{size}"
        return "ML-KEM"

    if "ML-DSA" in upper or "DILITHIUM" in upper:
        for param in ("87", "65", "44"):
            if param in upper:
                return f"ML-DSA-{param}"
        return "ML-DSA"

    if "SLH-DSA" in upper or "SPHINCS" in upper:
        return "SLH-DSA"

    # RSA variations
    if "RSA" in upper:
        m = re.search(r"\b(1024|2048|3072|4096)\b", upper)
        if m:
            return f"RSA-{m.group(1)}"
        if "OAEP" in upper:
            return "RSAES-OAEP"
        if "PSS" in upper:
            return "RSASSA-PSS"
        return "RSA"

    # Ed25519 & EdDSA
    if "ED25519" in upper:
        return "Ed25519"
    if "EDDSA" in upper:
        return "EdDSA"

    # Curves & ECC
    if "X25519" in upper or "CURVE25519" in upper:
        return "X25519"
    if "P-256" in upper or "SECP256R1" in upper or "PRIME256V1" in upper:
        return "ECDSA P-256"
    if "P-384" in upper or "SECP384R1" in upper:
        return "ECDSA P-384"
    if "P-521" in upper or "SECP521R1" in upper:
        return "ECDSA P-521"
    if "ECDSA" in upper:
        return "ECDSA"
    if "ECDH" in upper:
        return "ECDH"

    # AES variations
    if "AES" in upper:
        size = ""
        for s in ("256", "192", "128"):
            if s in upper:
                size = s
                break

        mode = ""
        for m_name in ("GCM", "CBC", "ECB", "CTR", "CFB", "OFB"):
            if m_name in upper:
                mode = m_name
                break

        if size and mode:
            return f"AES-{size}-{mode}"
        if size:
            return f"AES-{size}"
        if mode:
            return f"AES-{mode}"
        return "AES"

    # Hashes
    if "MD5" in upper:
        return "MD5"
    if "SHA-1" in upper or "SHA1" in upper:
        return "SHA-1"
    if "SHA-256" in upper or "SHA256" in upper:
        return "SHA-256"
    if "SHA-384" in upper or "SHA384" in upper:
        return "SHA-384"
    if "SHA-512" in upper or "SHA512" in upper:
        return "SHA-512"

    # MACs & KDF
    if "HMAC" in upper:
        if "384" in upper:
            return "HMAC-SHA384"
        if "512" in upper:
            return "HMAC-SHA512"
        return "HMAC-SHA256"
    if "PBKDF2" in upper:
        return "PBKDF2-HMAC-SHA256"

    # Legacy
    if "3DES" in upper or "TRIPLEDES" in upper or "TDES" in upper:
        return "3DES"
    if re.search(r"\bDES\b", upper):
        return "DES"

    return cleaned


def oid_for(algorithm_name: str) -> str:
    """Return standard dotted-decimal OID string or 'unknown'."""
    if not algorithm_name or not algorithm_name.strip():
        return "unknown"

    norm = algorithm_name.strip().upper().replace("_", "-").replace(" ", "-")

    if norm in OID_MAP:
        return OID_MAP[norm]

    # Partial or normalized key matching
    canonical = normalise(algorithm_name).upper().replace(" ", "-")
    if canonical in OID_MAP:
        return OID_MAP[canonical]

    # Match primary algorithm prefix/token
    for key, oid in OID_MAP.items():
        if key in norm or norm in key:
            return oid

    return "unknown"


def get_primitive_category(algorithm_name: str) -> str:
    """Return cryptographic primitive classification category."""
    if not algorithm_name or not algorithm_name.strip():
        return "unknown"

    norm = algorithm_name.strip().upper()

    if any(k in norm for k in ("ML-KEM", "KYBER")):
        return "kem"
    if any(k in norm for k in ("ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS", "RSA", "ECDSA", "ED25519", "EDDSA", "DSA")):
        return "signature"
    if any(k in norm for k in ("ECDH", "X25519", "DIFFIE-HELLMAN", "DH")):
        return "key-exchange"
    if "AES" in norm or "DES" in norm or "3DES" in norm or "CHACHA" in norm:
        return "block-cipher"
    if "HMAC" in norm:
        return "mac"
    if "PBKDF2" in norm or "HKDF" in norm or "SCRYPT" in norm or "ARGON2" in norm:
        return "kdf"
    if any(k in norm for k in ("SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5", "SHA1", "SHA256")):
        return "hash"

    return "unknown"


def is_pqc_native(algorithm_name: str) -> bool:
    """Return True if algorithm is a standardized Post-Quantum Cryptography primitive."""
    if not algorithm_name:
        return False
    norm = algorithm_name.strip().upper()
    return any(
        k in norm
        for k in (
            "ML-KEM",
            "KYBER",
            "ML-DSA",
            "DILITHIUM",
            "SLH-DSA",
            "SPHINCS",
            "FIPS 203",
            "FIPS 204",
            "FIPS 205",
        )
    )

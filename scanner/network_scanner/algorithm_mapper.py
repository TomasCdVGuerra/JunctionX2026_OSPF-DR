"""Offline TLS registries and network finding helpers.

Mappings are deliberately finite: unfamiliar identifiers remain unknown findings.
Sources: https://www.iana.org/assignments/tls-parameters/,
RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 8996 and RFC 9325.
The risk labels are local audit policy, not a claim that a whole connection is safe.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel

RiskAssessment = tuple[QuantumRiskLevel, QuantumRiskLevel, str, str]
Observation = Literal["declared", "configured", "advertised", "negotiated", "observed"]


@dataclass(frozen=True)
class Primitive:
    algorithm_name: str
    crypto_function: CryptoFunction
    key_size: int | None = None
    mode: str | None = None
    padding: str | None = None


@dataclass(frozen=True)
class CipherSuite:
    name: str
    key_exchange: str | None
    authentication: str | None
    cipher: str
    key_size: int | None
    mode: str | None
    hash_name: str
    tls13: bool = False


def _suite(name: str, kex: str | None, auth: str | None, cipher: str,
           bits: int | None, mode: str | None, digest: str, tls13: bool = False) -> CipherSuite:
    return CipherSuite(name, kex, auth, cipher, bits, mode, digest, tls13)


# Numeric IANA assignments, not OpenSSL aliases. TLS 1.3 suites do not identify
# authentication or key exchange; those require separate handshake evidence.
CIPHER_SUITES: dict[int, CipherSuite] = {
    0x0001: _suite("TLS_RSA_WITH_NULL_MD5", "RSA", None, "NULL", None, None, "MD5"),
    0x0002: _suite("TLS_RSA_WITH_NULL_SHA", "RSA", None, "NULL", None, None, "SHA-1"),
    0x0004: _suite("TLS_RSA_WITH_RC4_128_MD5", "RSA", None, "RC4", 128, None, "MD5"),
    0x0005: _suite("TLS_RSA_WITH_RC4_128_SHA", "RSA", None, "RC4", 128, None, "SHA-1"),
    0x0009: _suite("TLS_RSA_WITH_DES_CBC_SHA", "RSA", None, "DES", 56, "CBC", "SHA-1"),
    0x000A: _suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", None, "3DES", 168, "CBC", "SHA-1"),
    0x0016: _suite("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", "3DES", 168, "CBC", "SHA-1"),
    0x002F: _suite("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", None, "AES", 128, "CBC", "SHA-1"),
    0x0033: _suite("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES", 128, "CBC", "SHA-1"),
    0x0035: _suite("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", None, "AES", 256, "CBC", "SHA-1"),
    0x0039: _suite("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "AES", 256, "CBC", "SHA-1"),
    0x003C: _suite("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", None, "AES", 128, "CBC", "SHA-256"),
    0x003D: _suite("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", None, "AES", 256, "CBC", "SHA-256"),
    0x0067: _suite("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "AES", 128, "CBC", "SHA-256"),
    0x006B: _suite("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "AES", 256, "CBC", "SHA-256"),
    0x009C: _suite("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", None, "AES", 128, "GCM", "SHA-256"),
    0x009D: _suite("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", None, "AES", 256, "GCM", "SHA-384"),
    0x009E: _suite("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "AES", 128, "GCM", "SHA-256"),
    0x009F: _suite("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "AES", 256, "GCM", "SHA-384"),
    0xC009: _suite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", "AES", 128, "CBC", "SHA-1"),
    0xC00A: _suite("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", "AES", 256, "CBC", "SHA-1"),
    0xC013: _suite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "AES", 128, "CBC", "SHA-1"),
    0xC014: _suite("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", "AES", 256, "CBC", "SHA-1"),
    0xC023: _suite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", "AES", 128, "CBC", "SHA-256"),
    0xC024: _suite("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", "AES", 256, "CBC", "SHA-384"),
    0xC027: _suite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "AES", 128, "CBC", "SHA-256"),
    0xC028: _suite("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES", 256, "CBC", "SHA-384"),
    0xC02B: _suite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AES", 128, "GCM", "SHA-256"),
    0xC02C: _suite("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AES", 256, "GCM", "SHA-384"),
    0xC02F: _suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES", 128, "GCM", "SHA-256"),
    0xC030: _suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES", 256, "GCM", "SHA-384"),
    0xCCA8: _suite("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", "ChaCha20-Poly1305", 256, None, "SHA-256"),
    0xCCA9: _suite("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", "ChaCha20-Poly1305", 256, None, "SHA-256"),
    0xCCAA: _suite("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", "RSA", "ChaCha20-Poly1305", 256, None, "SHA-256"),
    0x1301: _suite("TLS_AES_128_GCM_SHA256", None, None, "AES", 128, "GCM", "SHA-256", True),
    0x1302: _suite("TLS_AES_256_GCM_SHA384", None, None, "AES", 256, "GCM", "SHA-384", True),
    0x1303: _suite("TLS_CHACHA20_POLY1305_SHA256", None, None, "ChaCha20-Poly1305", 256, None, "SHA-256", True),
    0x1304: _suite("TLS_AES_128_CCM_SHA256", None, None, "AES", 128, "CCM", "SHA-256", True),
    0x1305: _suite("TLS_AES_128_CCM_8_SHA256", None, None, "AES", 128, "CCM_8", "SHA-256", True),
}

GROUPS: dict[int, Primitive] = {
    23: Primitive("ECDHE-secp256r1", CryptoFunction.KEY_EXCHANGE, 256),
    24: Primitive("ECDHE-secp384r1", CryptoFunction.KEY_EXCHANGE, 384),
    25: Primitive("ECDHE-secp521r1", CryptoFunction.KEY_EXCHANGE, 521),
    29: Primitive("ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255),
    30: Primitive("ECDHE-X448", CryptoFunction.KEY_EXCHANGE, 448),
    256: Primitive("DHE-ffdhe2048", CryptoFunction.KEY_EXCHANGE, 2048),
    257: Primitive("DHE-ffdhe3072", CryptoFunction.KEY_EXCHANGE, 3072),
    258: Primitive("DHE-ffdhe4096", CryptoFunction.KEY_EXCHANGE, 4096),
    259: Primitive("DHE-ffdhe6144", CryptoFunction.KEY_EXCHANGE, 6144),
    260: Primitive("DHE-ffdhe8192", CryptoFunction.KEY_EXCHANGE, 8192),
    512: Primitive("ML-KEM-512", CryptoFunction.KEY_EXCHANGE),
    513: Primitive("ML-KEM-768", CryptoFunction.KEY_EXCHANGE),
    514: Primitive("ML-KEM-1024", CryptoFunction.KEY_EXCHANGE),
    # Preserve the hybrid construction, rather than flagging its classical
    # component alone as if it represented the complete shared secret.
    4587: Primitive("SecP256r1MLKEM768", CryptoFunction.KEY_EXCHANGE),
    4588: Primitive("X25519MLKEM768", CryptoFunction.KEY_EXCHANGE),
    4589: Primitive("SecP384r1MLKEM1024", CryptoFunction.KEY_EXCHANGE),
    25497: Primitive("X25519Kyber768Draft00", CryptoFunction.KEY_EXCHANGE),
    25498: Primitive("SecP256r1Kyber768Draft00", CryptoFunction.KEY_EXCHANGE),
}

# SignatureScheme, not the older one-byte SignatureAlgorithm registry.
SIGNATURE_SCHEMES: dict[int, tuple[Primitive, ...]] = {}
for _prefix, _name, _padding in ((1, "RSA", "PKCS1v15"), (2, "DSA", None), (3, "ECDSA", None)):
    for _hash_id, _hash in ((2, "SHA-1"), (4, "SHA-256"), (5, "SHA-384"), (6, "SHA-512")):
        SIGNATURE_SCHEMES[(_hash_id << 8) | _prefix] = (
            Primitive(_name, CryptoFunction.SIGN, padding=_padding),
            Primitive(_hash, CryptoFunction.DIGEST),
        )
for _identifier, _hash in ((0x0804, "SHA-256"), (0x0805, "SHA-384"), (0x0806, "SHA-512"),
                          (0x0809, "SHA-256"), (0x080A, "SHA-384"), (0x080B, "SHA-512")):
    SIGNATURE_SCHEMES[_identifier] = (
        Primitive("RSA", CryptoFunction.SIGN, padding="PSS"),
        Primitive(_hash, CryptoFunction.DIGEST),
    )
SIGNATURE_SCHEMES[0x0807] = (Primitive("Ed25519", CryptoFunction.SIGN, 255),)
SIGNATURE_SCHEMES[0x0808] = (Primitive("Ed448", CryptoFunction.SIGN, 448),)


def parse_identifier(value: str | int | None) -> int | None:
    """Accept decimal TShark values and hexadecimal IDs, including leading zeros."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        identifier = value
    elif isinstance(value, str):
        raw = value.strip().lower()
        if re.fullmatch(r"0x[0-9a-f]+", raw):
            identifier = int(raw, 16)
        elif re.fullmatch(r"[0-9]+", raw):
            identifier = int(raw, 10)
        elif re.fullmatch(r"[0-9a-f]+", raw):
            identifier = int(raw, 16)
        else:
            return None
    else:
        return None
    return identifier if 0 <= identifier <= 65535 else None


def is_grease(identifier: int | None) -> bool:
    """The sixteen RFC 8701 reserved two-byte GREASE values."""
    return identifier is not None and (identifier & 0x0F0F) == 0x0A0A and identifier >> 8 == identifier & 0xFF


def identifier_label(value: str | int) -> str:
    parsed = parse_identifier(value)
    return f"0x{parsed:04x}" if parsed is not None else str(value)


def cipher_primitives(suite: CipherSuite, version: str | None) -> list[Primitive]:
    primitives = []
    if suite.key_exchange:
        primitives.append(Primitive(suite.key_exchange, CryptoFunction.KEY_EXCHANGE))
    if suite.authentication:
        primitives.append(Primitive(suite.authentication, CryptoFunction.SIGN))
    primitives.append(Primitive(suite.cipher, CryptoFunction.ENCRYPT, suite.key_size, suite.mode))
    primitives.append(Primitive(suite.hash_name, CryptoFunction.DIGEST))
    if suite.tls13:
        primitives.append(Primitive(f"HKDF-{suite.hash_name}", CryptoFunction.KDF))
    else:
        if suite.mode == "CBC" or suite.cipher in {"RC4", "NULL"}:
            primitives.append(Primitive(f"HMAC-{suite.hash_name}", CryptoFunction.MAC))
        if version == "TLS 1.2":
            # SHA-1 in older suite names denotes the record MAC. TLS 1.2's
            # default PRF is SHA-256, not SHA-1 (RFC 5246, section 5).
            prf_hash = suite.hash_name if suite.hash_name in {"SHA-256", "SHA-384"} else "SHA-256"
            primitives.append(Primitive(f"TLS-PRF-{prf_hash}", CryptoFunction.KDF))
        elif version in {"TLS 1.0", "TLS 1.1"}:
            primitives.append(Primitive("TLS-PRF-MD5-SHA-1", CryptoFunction.KDF))
    return primitives


def assess_primitive(algorithm_name: str, key_size: int | None = None,
                     mode: str | None = None,
                     crypto_function: CryptoFunction = CryptoFunction.UNKNOWN) -> RiskAssessment:
    """Classify an observed primitive, with unknown sizes kept unknown.

    AES-128's medium quantum label is a conservative margin policy. NIST's
    PQC FAQ permits continued AES-128 use; this label does not claim a break.
    SHA-1 collisions are not evidence that HMAC-SHA-1 is broken.
    """
    Q = QuantumRiskLevel
    name = algorithm_name.upper().replace("_", "-")
    unknown = (Q.UNKNOWN, Q.UNKNOWN, "No verified primitive mapping is available; risk cannot be inferred from the identifier.",
               "Resolve the identifier against its protocol registry and review the cryptographic configuration.")
    if name in {"X25519KYBER768DRAFT00", "SECP256R1KYBER768DRAFT00"}:
        return (Q.UNKNOWN, Q.MEDIUM, "An obsolete pre-standard Kyber hybrid was advertised or selected; it is not FIPS 203 ML-KEM.",
                "Replace the draft hybrid with a supported standardized ML-KEM hybrid.")
    if name in {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "SECP256R1MLKEM768",
                "X25519MLKEM768", "SECP384R1MLKEM1024", "MLKEM768X25519", "SNTRUP761X25519"}:
        return (Q.SAFE, Q.SAFE, "This identified post-quantum KEM or hybrid has no known Shor-style break; this is a primitive assessment, not a full-session guarantee.",
                "Retain supported implementations and review authentication separately for post-quantum migration.")
    if name in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
        return (Q.SAFE, Q.SAFE, "The identified post-quantum signature construction is designed to resist known quantum attacks.",
                "Retain supported standardized implementations and monitor migration guidance.")
    if name in {"NULL", "NONE", "DES", "3DES", "TRIPLEDES", "RC4"}:
        return (Q.CRITICAL if name not in {"NULL", "NONE"} else Q.UNKNOWN, Q.CRITICAL,
                "Encryption is absent or uses an obsolete cipher with inadequate modern classical security.",
                "Disable this option and use an authenticated cipher such as AES-GCM or ChaCha20-Poly1305.")
    if name == "AES":
        if key_size not in {128, 192, 256}:
            return unknown
        quantum = Q.SAFE if key_size == 256 else Q.MEDIUM
        classical = Q.MEDIUM if mode and mode.upper() in {"CBC", "CCM_8"} else Q.SAFE
        return (quantum, classical,
                "AES has no Shor-style break. The quantum label expresses conservative key-search margin; NIST permits AES-128/192/256. CBC or a short CCM tag requires protocol-specific review." if classical == Q.MEDIUM else
                "AES has no Shor-style break. The quantum label expresses conservative key-search margin; NIST permits AES-128/192/256.",
                "Prefer AES-256-GCM for a conservative quantum margin and authenticated encryption.")
    if name in {"CHACHA20", "CHACHA20-POLY1305"}:
        return (Q.SAFE, Q.SAFE, "The identified 256-bit symmetric cipher has a substantial margin against generic quantum key search.",
                "Retain ChaCha20-Poly1305 with correct nonce handling and review key exchange separately.")
    keyed = {f"{prefix}-{digest}" for prefix in ("HMAC", "HKDF", "TLS-PRF")
             for digest in ("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512")}
    if name in keyed or name == "TLS-PRF-MD5-SHA-1":
        if "MD5" in name or "SHA-1" in name:
            return (Q.MEDIUM, Q.MEDIUM, "This is a legacy keyed construction. Digest collision attacks alone do not establish an HMAC break; exact security depends on keying and protocol use.",
                    "Prefer an SHA-256 or SHA-384 keyed construction and modern TLS.")
        if any(digest in name for digest in ("SHA-256", "SHA-384", "SHA-512")):
            return (Q.SAFE, Q.SAFE, "The identified SHA-2 keyed construction has no known Shor-style attack; secret input quality remains relevant.",
                    "Retain the SHA-2 construction and ensure sufficient secret key entropy.")
        return unknown
    if name in {"SHA-1", "MD5"}:
        return (Q.CRITICAL, Q.CRITICAL, "The standalone digest has known classical collision weaknesses and insufficient modern collision security.",
                "Replace standalone uses with SHA-256 or stronger; assess keyed HMAC uses separately.")
    if name in {"SHA-256", "SHA-384", "SHA-512"}:
        return (Q.MEDIUM if name == "SHA-256" else Q.SAFE, Q.SAFE,
                "The digest remains classically sound; generic quantum collision attacks reduce its collision-security margin.",
                "Use SHA-384 or stronger where a conservative quantum collision margin is required.")
    public_key = {"RSA", "DSA", "DH", "DHE", "ECDH", "ECDHE", "ECDSA", "ED25519", "ED448"}
    public_key.update(primitive.algorithm_name.upper() for primitive in GROUPS.values()
                      if primitive.algorithm_name.startswith(("ECDHE-", "DHE-")))
    if name in public_key:
        classical = Q.UNKNOWN
        if name.startswith(("ECDH", "ECDSA", "ED25519", "ED448")) and (key_size is not None or name.startswith(("ED25519", "ED448"))):
            classical = Q.SAFE if key_size is None or key_size >= 224 else Q.CRITICAL
        elif key_size is not None:
            classical = Q.SAFE if key_size >= 2048 else Q.CRITICAL
        if name.startswith("RSA") and crypto_function == CryptoFunction.KEY_EXCHANGE:
            if classical == Q.SAFE:
                classical = Q.MEDIUM
            reason = "RSA key transport is vulnerable to Shor's algorithm and provides no forward secrecy; the RSA modulus size is not inferred from the suite."
        else:
            reason = "This classical public-key primitive is vulnerable to Shor's algorithm. A missing key/group size prevents a complete classical-strength assessment."
        return (Q.CRITICAL, classical, reason,
                "Plan migration to ML-KEM or a supported hybrid for key establishment, and ML-DSA/SLH-DSA for signatures; retain adequate classical key sizes during transition.")
    return unknown


def network_evidence(path: Path, entry: dict, rule_id: str, *, reasoning: str | None = None) -> Evidence:
    raw_packet = entry.get("packet_number")
    packet = None
    if isinstance(raw_packet, int) and not isinstance(raw_packet, bool):
        packet = raw_packet
    elif isinstance(raw_packet, str):
        normalized = raw_packet.strip()
        if re.fullmatch(r"[0-9]+", normalized):
            packet = int(normalized)
    if packet is not None and packet < 1:
        packet = None
    snippet = entry.get("matched_snippet")
    if not isinstance(snippet, str):
        snippet = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
    return Evidence(file_path=str(path), packet_number=packet, matched_snippet=snippet,
                    rule_id=rule_id, risk_reasoning=reasoning)


def make_finding(path: Path, entry: dict, *, algorithm_name: str, rule_id: str,
                 observation: Observation, asset_type: AssetType = AssetType.ALGORITHM,
                 key_size: int | None = None, mode: str | None = None,
                 padding: str | None = None, crypto_function: CryptoFunction = CryptoFunction.UNKNOWN,
                 protocol: str | None = None, confidence: Literal["low", "medium", "high"] = "high",
                 risk_override: RiskAssessment | None = None) -> CryptoFinding:
    quantum, classical, reason, recommendation = risk_override or assess_primitive(
        algorithm_name, key_size, mode, crypto_function)
    return CryptoFinding(algorithm_name=algorithm_name, asset_type=asset_type,
                         source_type="network-capture", key_size=key_size, mode=mode, padding=padding,
                         protocol=protocol, crypto_function=crypto_function, observation=observation,
                         quantum_risk=quantum, classical_risk=classical, confidence=confidence,
                         evidence=[network_evidence(path, entry, rule_id, reasoning=reason)],
                         recommendation=recommendation)

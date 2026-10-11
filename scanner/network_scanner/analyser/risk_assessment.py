"""Shared risk policy and assessed finding construction for network analyzers.

Protocol-specific decisions belong to each analyzer. Common primitive rules
are defined here so TLS and SSH can apply the same local audit policy.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from scanner.models import AssetType, CryptoFinding, CryptoFunction, QuantumRiskLevel
from scanner.network_scanner.algorithm_mapper import (
    GROUPS,
    Observation,
    network_evidence,
)

RiskAssessment = tuple[
    QuantumRiskLevel,
    QuantumRiskLevel,
    str,
    str,
]


def assess_primitive(
    algorithm_name: str,
    key_size: int | None = None,
    mode: str | None = None,
    crypto_function: CryptoFunction = CryptoFunction.UNKNOWN,
) -> RiskAssessment:
    """Aplicar a politica local de risco a uma primitiva identificada."""

    Q = QuantumRiskLevel
    name = algorithm_name.upper().replace("_", "-")

    unknown: RiskAssessment = (
        Q.UNKNOWN,
        Q.UNKNOWN,
        (
            "No verified primitive mapping or sufficient parameters are "
            "available; risk cannot be fully assessed."
        ),
        (
            "Resolve the identifier and review the cryptographic "
            "parameters and configuration."
        ),
    )

    if name in {
        "X25519KYBER768DRAFT00",
        "SECP256R1KYBER768DRAFT00",
    }:
        return (
            Q.UNKNOWN,
            Q.MEDIUM,
            (
                "An obsolete pre-standard Kyber hybrid was advertised or "
                "selected; it is not FIPS 203 ML-KEM."
            ),
            "Replace the draft hybrid with a supported ML-KEM hybrid.",
        )

    if name in {
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "SECP256R1MLKEM768",
        "X25519MLKEM768",
        "SECP384R1MLKEM1024",
        "MLKEM768X25519",
        "SNTRUP761X25519",
    }:
        return (
            Q.SAFE,
            Q.SAFE,
            (
                "This identified post-quantum KEM or hybrid has no known "
                "Shor-style break. This is a primitive assessment, "
                "not a full-session guarantee."
            ),
            (
                "Retain supported implementations and review "
                "authentication separately."
            ),
        )

    if name in {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
        return (
            Q.SAFE,
            Q.SAFE,
            (
                "The identified post-quantum signature construction "
                "is designed to resist known quantum attacks."
            ),
            (
                "Retain supported standardized implementations "
                "and monitor migration guidance."
            ),
        )

    if name in {"NULL", "NONE", "DES", "3DES", "TRIPLEDES", "RC4"}:
        return (
            Q.UNKNOWN if name in {"NULL", "NONE"} else Q.CRITICAL,
            Q.CRITICAL,
            (
                "Encryption is absent or uses an obsolete cipher "
                "with inadequate modern classical security."
            ),
            (
                "Disable this option and use authenticated encryption "
                "such as AES-GCM or ChaCha20-Poly1305."
            ),
        )

    if name == "AES":
        normalized_mode = mode.strip().upper() if isinstance(mode, str) else None
        if normalized_mode == "ECB":
            return (
                Q.UNKNOWN if key_size not in {128, 192, 256} else Q.SAFE if key_size == 256 else Q.MEDIUM,
                Q.CRITICAL,
                "AES-ECB exposes repeated-block patterns independently of key size. "
                "Missing or unsupported key size leaves the quantum assessment unknown.",
                "Replace ECB with authenticated encryption and confirm the key size and nonce handling.",
            )
        if key_size not in {128, 192, 256}:
            return unknown

        quantum = Q.SAFE if key_size == 256 else Q.MEDIUM
        if normalized_mode in {"CBC", "CCM_8"}:
            classical = Q.MEDIUM
        elif normalized_mode in {"GCM", "CCM", "CTR"}:
            classical = Q.SAFE
        else:
            classical = Q.UNKNOWN

        reason = (
            "AES has no Shor-style break. The quantum label expresses "
            "a conservative key-search margin policy."
        )

        if classical == Q.MEDIUM:
            reason += (
                " CBC or a short CCM tag requires "
                "protocol-specific review."
            )
        elif classical == Q.UNKNOWN:
            reason += (
                " The AES mode is missing or unsupported by this policy; "
                "the classical configuration assessment remains unknown."
            )

        return (
            quantum,
            classical,
            reason,
            (
                "Prefer AES-256-GCM for a conservative quantum "
                "margin and authenticated encryption."
            ),
        )

    if name in {"CHACHA20", "CHACHA20-POLY1305"}:
        return (
            Q.SAFE,
            Q.SAFE,
            (
                "The identified 256-bit symmetric cipher has a "
                "substantial margin against generic quantum key search."
            ),
            (
                "Retain ChaCha20-Poly1305 with correct nonce handling "
                "and review key exchange separately."
            ),
        )

    keyed = {
        f"{prefix}-{digest}"
        for prefix in ("HMAC", "HKDF", "TLS-PRF")
        for digest in (
            "MD5",
            "SHA-1",
            "SHA-256",
            "SHA-384",
            "SHA-512",
        )
    }

    if name in keyed or name == "TLS-PRF-MD5-SHA-1":
        if "MD5" in name or "SHA-1" in name:
            return (
                Q.MEDIUM,
                Q.MEDIUM,
                (
                    "This is a legacy keyed construction. Digest "
                    "collision attacks alone do not establish an "
                    "HMAC break; security depends on protocol use."
                ),
                (
                    "Prefer an SHA-256 or SHA-384 keyed "
                    "construction and modern TLS."
                ),
            )

        return (
            Q.UNKNOWN,
            Q.UNKNOWN,
            (
                "The advertised or selected SHA-2 keyed construction alone does not "
                "establish secret input entropy or complete MAC/KDF parameters. "
                "Both risk assessments remain unknown; a digest name or key length "
                "does not prove secret input quality."
            ),
            (
                "Verify secret input entropy and protocol-specific parameters "
                "(including MAC tag length or KDF context) before concluding safety."
            ),
        )

    if name in {"SHA-1", "MD5"}:
        return (
            Q.CRITICAL,
            Q.CRITICAL,
            (
                "The standalone digest has known classical collision "
                "weaknesses and insufficient modern collision security."
            ),
            (
                "Replace standalone uses with SHA-256 or stronger; "
                "assess keyed HMAC uses separately."
            ),
        )

    if name in {"SHA-256", "SHA-384", "SHA-512"}:
        return (
            Q.MEDIUM if name == "SHA-256" else Q.SAFE,
            Q.SAFE,
            (
                "The digest remains classically sound; generic quantum "
                "collision attacks reduce its collision-security margin."
            ),
            (
                "Use SHA-384 or stronger where a conservative "
                "quantum collision margin is required."
            ),
        )

    public_key = {
        "RSA",
        "DSA",
        "DH",
        "DHE",
        "ECDH",
        "ECDHE",
        "ECDSA",
        "ED25519",
        "ED448",
    }

    public_key.update(
        primitive.algorithm_name.upper()
        for primitive in GROUPS.values()
        if primitive.algorithm_name.startswith(("ECDHE-", "DHE-"))
    )

    if name in public_key:
        classical = Q.UNKNOWN

        if name.startswith(("ECDH", "ECDSA", "ED25519", "ED448")):
            if key_size is not None:
                classical = Q.SAFE if key_size >= 224 else Q.CRITICAL
            elif name.startswith(("ED25519", "ED448")):
                classical = Q.SAFE

        elif key_size is not None:
            classical = Q.SAFE if key_size >= 2048 else Q.CRITICAL

        if name == "RSA" and crypto_function == CryptoFunction.KEY_EXCHANGE:
            # Preservar UNKNOWN quando o tamanho RSA nao e conhecido.
            if classical == Q.SAFE:
                classical = Q.MEDIUM

            reason = (
                "RSA key transport is vulnerable to Shor's algorithm "
                "and provides no forward secrecy."
            )
            if key_size is None:
                reason += (
                    " The RSA modulus size is unknown "
                    "and is not inferred from the cipher suite."
                )
        else:
            reason = (
                "This classical public-key primitive is vulnerable "
                "to Shor's algorithm."
            )
            if classical == Q.UNKNOWN:
                reason += (
                    " A missing key or group size prevents "
                    "a complete classical-strength assessment."
                )

        return (
            Q.CRITICAL,
            classical,
            reason,
            (
                "Plan migration to ML-KEM or a supported hybrid for "
                "key establishment, and ML-DSA/SLH-DSA for signatures; "
                "retain adequate classical key sizes during transition."
            ),
        )

    return unknown


def enrich_finding(
    finding: CryptoFinding,
    *,
    risk_override: RiskAssessment | None = None,
) -> CryptoFinding:
    """Return a validated assessment while preserving the original observation."""
    assessment = (
        risk_override
        if risk_override is not None
        else assess_primitive(
            finding.algorithm_name,
            finding.key_size,
            finding.mode,
            finding.crypto_function,
        )
    )
    quantum, classical, reason, recommendation = assessment
    data = finding.model_dump()
    data.update(
        quantum_risk=quantum,
        classical_risk=classical,
        recommendation=recommendation,
    )
    for evidence in data["evidence"]:
        evidence["risk_reasoning"] = reason
    return CryptoFinding.model_validate(data)


def make_finding(
    path: Path,
    entry: dict,
    *,
    algorithm_name: str,
    rule_id: str,
    observation: Observation,
    asset_type: AssetType = AssetType.ALGORITHM,
    key_size: int | None = None,
    mode: str | None = None,
    padding: str | None = None,
    crypto_function: CryptoFunction = CryptoFunction.UNKNOWN,
    protocol: str | None = None,
    confidence: Literal["low", "medium", "high"] = "high",
    risk_override: RiskAssessment | None = None,
) -> CryptoFinding:
    """Construir um resultado com avaliacao de risco e evidencia."""
    finding = CryptoFinding(
        algorithm_name=algorithm_name,
        asset_type=asset_type,
        source_type="network-capture",
        key_size=key_size,
        mode=mode,
        padding=padding,
        protocol=protocol,
        crypto_function=crypto_function,
        observation=observation,
        confidence=confidence,
        evidence=[
            network_evidence(
                path,
                entry,
                rule_id,
            )
        ],
    )
    return enrich_finding(finding, risk_override=risk_override)

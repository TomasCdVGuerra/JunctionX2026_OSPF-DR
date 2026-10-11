"""Centralized post-quantum and classical risk evaluation engine.

Dual-Axis Risk Model:
- quantum_risk: Future quantum vulnerability (e.g. exposure to Shor's algorithm for
  factoring/discrete logarithms, or Grover's algorithm for symmetric search).
- classical_risk: Current classical cryptographic strength (e.g. exposure to known
  classical cryptanalysis, collision attacks, or weak key sizes under pre-quantum threat models).

Distinction Example:
- RSA-2048:
    * quantum_risk = CRITICAL (vulnerable to Shor's algorithm; must be migrated to PQC)
    * classical_risk = SAFE (provides ~112 bits of classical security; not classically broken today)
- RSA-1024:
    * quantum_risk = CRITICAL (vulnerable to Shor's algorithm)
    * classical_risk = MEDIUM (classically deprecated/weak parameter size)
- MD5 / SHA-1 / DES:
    * quantum_risk = CRITICAL
    * classical_risk = CRITICAL (classically broken via known practical attacks)
"""

from __future__ import annotations

import re

from scanner.models import CryptoFinding, QuantumRiskLevel


def normalise_algorithm_name(raw_name: str) -> str:
    """Standardize algorithm string for consistent risk matching."""
    if not raw_name:
        return "unknown"
    cleaned = raw_name.strip()
    return cleaned if cleaned else "unknown"


def algorithm_family(algorithm_name: str) -> str:
    """Return top-level cryptographic family or primitive type."""
    norm = algorithm_name.strip().upper()
    if "RSA" in norm:
        return "RSA"
    if "ED25519" in norm or "EDDSA" in norm:
        return "EdDSA"
    if "ECDSA" in norm or "ECDH" in norm or "ECC" in norm or "SECP" in norm or "PRIME256" in norm:
        return "ECC"
    if "CURVE25519" in norm or "X25519" in norm:
        return "X25519"
    if "AES" in norm:
        return "AES"
    if "MD5" in norm:
        return "MD5"
    if "SHA-1" in norm or "SHA1" in norm:
        return "SHA-1"
    if "SHA-256" in norm or "SHA256" in norm:
        return "SHA-256"
    if "SHA-384" in norm or "SHA384" in norm:
        return "SHA-384"
    if "SHA-512" in norm or "SHA512" in norm:
        return "SHA-512"
    if "HMAC" in norm:
        return "HMAC"
    if "PBKDF2" in norm:
        return "PBKDF2"
    if "ML-KEM" in norm or "KYBER" in norm:
        return "ML-KEM"
    if "ML-DSA" in norm or "DILITHIUM" in norm:
        return "ML-DSA"
    if "SLH-DSA" in norm or "SPHINCS" in norm:
        return "SLH-DSA"
    if "DES" in norm:
        return "DES"
    if "DH" in norm or "DIFFIE-HELLMAN" in norm:
        return "DH"
    if "DSA" in norm:
        return "DSA"
    return "UNKNOWN"


def is_shor_vulnerable(algorithm_name: str) -> bool:
    """Return True if algorithm relies on integer factoring or discrete log broken by Shor."""
    if not algorithm_name:
        return False
    norm = algorithm_name.strip().upper()
    if any(k in norm for k in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS")):
        return False
    shor_keywords = (
        "RSA",
        "ED25519",
        "EDDSA",
        "ECDSA",
        "ECDH",
        "ECC",
        "SECP256",
        "SECP384",
        "SECP521",
        "PRIME256",
        "CURVE25519",
        "X25519",
        "DIFFIE-HELLMAN",
    )
    if any(k in norm for k in shor_keywords):
        return True
    if re.search(r"\bDH\b", norm) or re.search(r"\bDHE\b", norm):
        return True
    return bool(
        re.search(r"\bDSA\b", norm)
        and "ML-DSA" not in norm
        and "SLH-DSA" not in norm
    )


def is_classically_broken(algorithm_name: str, mode: str | None = None) -> bool:
    """Return True if algorithm or mode is classically compromised."""
    norm = algorithm_name.strip().upper()
    mode_norm = (mode or "").strip().upper()
    if mode_norm == "ECB" or "ECB" in norm:
        return True
    if "MD5" in norm:
        return True
    if "SHA-1" in norm or "SHA1" in norm:
        return True
    if re.search(r"\bDES\b", norm) or "3DES" in norm or "TRIPLEDES" in norm or "TDES" in norm:
        return True
    return bool(
        "CLEARTEXT" in norm
        or "PLAINTEXT" in norm
    )


def estimate_classical_bits(
    algorithm_name: str,
    key_size: int | str | None = None,
) -> int | None:
    """Estimate classical security bit strength based on algorithm and key length."""
    norm = algorithm_name.strip().upper()
    num_key: int | None = None
    if isinstance(key_size, int):
        num_key = key_size
    elif isinstance(key_size, str) and key_size.isdigit():
        num_key = int(key_size)
    else:
        m = re.search(r"\b(1024|2048|3072|4096|128|192|256|384|512)\b", norm)
        if m:
            num_key = int(m.group(1))

    if is_classically_broken(algorithm_name):
        if "3DES" in norm or "TRIPLEDES" in norm:
            return 112
        if "DES" in norm:
            return 56
        return 0

    if "RSA" in norm:
        if num_key == 1024:
            return 80
        if num_key == 2048:
            return 112
        if num_key == 3072:
            return 128
        if num_key == 4096:
            return 152
        return num_key if num_key else None

    if any(k in norm for k in ("ED25519", "CURVE25519", "X25519", "P256", "PRIME256", "SECP256")):
        return 128
    if any(k in norm for k in ("P384", "SECP384")):
        return 192
    if any(k in norm for k in ("P521", "SECP521")):
        return 256
    if "ECDSA" in norm or "ECDH" in norm:
        return num_key // 2 if num_key else 128

    if "AES" in norm:
        if num_key in (128, 192, 256):
            return num_key
        return None

    if "SHA-256" in norm or "SHA256" in norm:
        return 128
    if "SHA-384" in norm or "SHA384" in norm:
        return 192
    if "SHA-512" in norm or "SHA512" in norm:
        return 256
    if "HMAC" in norm:
        if "384" in norm:
            return 192
        if "512" in norm:
            return 256
        return 128
    if "PBKDF2" in norm:
        return 128

    if any(k in norm for k in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS")):
        if "512" in norm or "2" in norm or "44" in norm:
            return 128
        if "768" in norm or "3" in norm or "65" in norm:
            return 192
        if "1024" in norm or "5" in norm or "87" in norm:
            return 256
        return 128

    return None


def estimate_quantum_bits(
    algorithm_name: str,
    key_size: int | str | None = None,
    mode: str | None = None,
) -> int | None:
    """Estimate post-quantum security bit strength under Shor's or Grover's algorithm."""
    if is_classically_broken(algorithm_name, mode):
        return 0

    if is_shor_vulnerable(algorithm_name):
        return 0

    norm = algorithm_name.strip().upper()
    num_key: int | None = None
    if isinstance(key_size, int):
        num_key = key_size
    elif isinstance(key_size, str) and key_size.isdigit():
        num_key = int(key_size)
    else:
        m = re.search(r"\b(128|192|256|384|512)\b", norm)
        if m:
            num_key = int(m.group(1))

    if "AES" in norm:
        if num_key == 128:
            return 64
        if num_key == 192:
            return 96
        if num_key == 256:
            return 128
        return None

    if "SHA-256" in norm or "SHA256" in norm:
        return 128
    if "SHA-384" in norm or "SHA384" in norm:
        return 192
    if "SHA-512" in norm or "SHA512" in norm:
        return 256

    if "HMAC" in norm:
        if "384" in norm:
            return 192
        if "512" in norm:
            return 256
        return 128

    if "PBKDF2" in norm:
        return 128

    if any(k in norm for k in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS")):
        if "512" in norm or "2" in norm or "44" in norm:
            return 128
        if "768" in norm or "3" in norm or "65" in norm:
            return 192
        if "1024" in norm or "5" in norm or "87" in norm:
            return 256
        return 128

    return None


def map_nist_standard(algorithm_name: str) -> str:
    """Return authoritative NIST standard publication reference or 'none'."""
    if not algorithm_name:
        return "none"

    norm = algorithm_name.strip().upper()

    # Post-Quantum FIPS standards
    if any(k in norm for k in ("ML-KEM", "KYBER")):
        return "FIPS 203"
    if any(k in norm for k in ("ML-DSA", "DILITHIUM")):
        return "FIPS 204"
    if any(k in norm for k in ("SLH-DSA", "SPHINCS")):
        return "FIPS 205"

    # Message authentication & KDF
    if "HMAC" in norm:
        return "FIPS 198-1"
    if "PBKDF2" in norm:
        return "SP 800-132"

    # Symmetric ciphers
    if "AES" in norm:
        return "FIPS 197"

    # Hash functions (check SHA-1/SHA-2 family before SHA-3 to avoid SHA-3 matching SHA-384)
    if any(k in norm for k in ("SHA-256", "SHA-384", "SHA-512", "SHA-224", "SHA-1", "SHA1", "SHA256", "SHA384", "SHA512")):
        return "FIPS 180-4"
    if any(k in norm for k in ("SHA3-", "SHA-3-", "SHAKE")) or re.search(r"\bSHA-?3\b", norm):
        return "FIPS 202"

    # Asymmetric signatures & key exchange
    if any(k in norm for k in ("RSA", "ECDSA", "ED25519", "EDDSA", "DSA")):
        return "FIPS 186-5"
    if any(k in norm for k in ("CURVE25519", "X25519")):
        return "SP 800-186"

    return "none"


def evaluate_risk(
    algorithm_name: str,
    key_size: int | str | None = None,
    mode: str | None = None,
) -> tuple[QuantumRiskLevel, int | None, int | None, str]:
    """Evaluate cryptographic primitive against classical and quantum threats.

    Returns:
        (risk_tier, estimated_classical_bits, estimated_quantum_bits, reasoning_sentence)
    """
    if not algorithm_name or algorithm_name.strip().lower() in ("unknown", "none", ""):
        return (
            QuantumRiskLevel.UNKNOWN,
            None,
            None,
            "Cryptographic algorithm is unspecified and cannot be evaluated.",
        )

    raw_algo = algorithm_name.strip()
    norm = raw_algo.upper()

    # Normalize integer key size if present
    num_key: int | None = None
    if isinstance(key_size, int):
        num_key = key_size
    elif isinstance(key_size, str) and key_size.isdigit():
        num_key = int(key_size)
    else:
        m = re.search(r"\b(1024|2048|3072|4096|128|192|256|384|512)\b", norm)
        if m:
            num_key = int(m.group(1))

    # Normalize mode if present
    mode_clean: str | None = None
    if mode:
        mode_clean = mode.strip().upper()
    else:
        for m_candidate in ("ECB", "GCM", "CBC", "CTR", "CFB", "OFB"):
            if re.search(rf"\b{m_candidate}\b", norm):
                mode_clean = m_candidate
                break

    # ---------------------------------------------------------
    # 1. Classical Compromises (Always CRITICAL)
    # ---------------------------------------------------------
    if mode_clean == "ECB" or "ECB" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "AES in ECB mode lacks semantic security and leaks plaintext patterns across identical blocks.",
        )

    if "MD5" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "MD5 is classically broken because practical collision attacks undermine its integrity guarantees.",
        )

    if "SHA-1" in norm or "SHA1" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "SHA-1 is deprecated and vulnerable to practical collision attacks.",
        )

    if re.search(r"\bDES\b", norm) and "3DES" not in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            56,
            0,
            "DES is classically broken due to its small 56-bit key space, vulnerable to practical brute-force attacks.",
        )

    if "3DES" in norm or "TRIPLEDES" in norm or "TDES" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            112,
            0,
            "3DES is deprecated and vulnerable to the Sweet32 collision attack due to its 64-bit block size.",
        )

    if "CLEARTEXT" in norm or "PLAINTEXT" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "Unencrypted cleartext traffic exposes data in transit without any cryptographic protection.",
        )

    # ---------------------------------------------------------
    # 2. Post-Quantum Cryptographic Standards (SAFE)
    # ---------------------------------------------------------
    if any(k in norm for k in ("ML-KEM", "KYBER")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} is a NIST FIPS 203 standardized post-quantum lattice-based key encapsulation mechanism.",
        )

    if any(k in norm for k in ("ML-DSA", "DILITHIUM")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} is a NIST FIPS 204 standardized post-quantum lattice-based digital signature algorithm.",
        )

    if any(k in norm for k in ("SLH-DSA", "SPHINCS")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} is a NIST FIPS 205 standardized post-quantum stateless hash-based digital signature algorithm.",
        )

    # ---------------------------------------------------------
    # 3. Shor-Vulnerable Asymmetric Schemes (Always CRITICAL)
    # ---------------------------------------------------------
    if "RSA" in norm:
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        size_label = f"-{num_key}" if num_key else ""
        return (
            QuantumRiskLevel.CRITICAL,
            cl_bits,
            0,
            f"RSA{size_label} is vulnerable to Shor's polynomial-time factoring algorithm regardless of classical key size.",
        )

    if "ED25519" in norm or "EDDSA" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            128,
            0,
            "Ed25519 signature algorithm is broken by Shor's quantum discrete-log algorithm.",
        )

    if any(k in norm for k in ("CURVE25519", "X25519")):
        return (
            QuantumRiskLevel.CRITICAL,
            128,
            0,
            "Curve25519 key exchange is broken by Shor's quantum discrete-log algorithm.",
        )

    if any(k in norm for k in ("ECDSA", "ECDH", "ECC", "SECP", "PRIME256")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.CRITICAL,
            cl_bits or 128,
            0,
            f"{raw_algo} elliptic-curve cryptography is broken by Shor's quantum discrete-log algorithm.",
        )

    if "DIFFIE-HELLMAN" in norm or re.search(r"\bDH\b", norm) or re.search(r"\bDHE\b", norm):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.CRITICAL,
            cl_bits,
            0,
            f"{raw_algo} finite-field Diffie-Hellman is vulnerable to Shor's quantum discrete-log algorithm.",
        )

    if re.search(r"\bDSA\b", norm) and "ML-DSA" not in norm and "SLH-DSA" not in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            80,
            0,
            "DSA signatures are broken by Shor's quantum discrete-log algorithm.",
        )

    # ---------------------------------------------------------
    # 4. Symmetric Hashes & MACs (SAFE)
    # ---------------------------------------------------------
    if "HMAC" in norm:
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} message authentication code is quantum-resistant against Grover's algorithm.",
        )

    if "PBKDF2" in norm:
        return (
            QuantumRiskLevel.SAFE,
            128,
            128,
            "PBKDF2 key derivation using SHA-256 is quantum-resistant against Grover's algorithm.",
        )

    if any(k in norm for k in ("SHA-256", "SHA256")):
        return (
            QuantumRiskLevel.SAFE,
            128,
            128,
            "SHA-256 hash function maintains 128 bits of quantum collision resistance against Grover's algorithm.",
        )

    if any(k in norm for k in ("SHA-384", "SHA384")):
        return (
            QuantumRiskLevel.SAFE,
            192,
            192,
            "SHA-384 hash function maintains 192 bits of quantum collision resistance against Grover's algorithm.",
        )

    if any(k in norm for k in ("SHA-512", "SHA512")):
        return (
            QuantumRiskLevel.SAFE,
            256,
            256,
            "SHA-512 hash function maintains 256 bits of quantum collision resistance against Grover's algorithm.",
        )

    # ---------------------------------------------------------
    # 5. Symmetric Ciphers (AES / Others)
    # ---------------------------------------------------------
    if "AES" in norm:
        # Check if mode is explicitly unknown or unresolvable
        if (
            mode_clean in ("UNKNOWN", "UNRESOLVED")
            or (mode is not None and mode.strip().lower() in ("unknown", "unresolved"))
            or "-UNKNOWN" in norm
        ):
            return (
                QuantumRiskLevel.UNKNOWN,
                None,
                None,
                "The AES key size or mode could not be proven statically, so the finding requires manual review.",
            )

        # AES mode must be proven statically; without mode information,
        # the scanner cannot distinguish secure modes (e.g. GCM) from insecure modes (e.g. ECB).
        if mode_clean is None:
            return (
                QuantumRiskLevel.UNKNOWN,
                None,
                None,
                "The AES mode or key size could not be proven statically, so the finding requires manual review.",
            )

        if num_key == 256:
            mode_desc = f"-{mode_clean}" if mode_clean and mode_clean != "256" else ""
            return (
                QuantumRiskLevel.SAFE,
                256,
                128,
                f"AES-256{mode_desc} retains approximately 128 bits of quantum security against Grover's algorithm.",
            )

        if num_key == 128:
            mode_desc = f"-{mode_clean}" if mode_clean and mode_clean != "128" else ""
            return (
                QuantumRiskLevel.MEDIUM,
                128,
                64,
                f"AES-128{mode_desc} provides only approximately 64 bits of effective quantum security under Grover's algorithm.",
            )

        if num_key == 192:
            return (
                QuantumRiskLevel.MEDIUM,
                192,
                96,
                "AES-192 provides approximately 96 bits of effective quantum security under Grover's algorithm.",
            )

        # AES with unresolved key size
        return (
            QuantumRiskLevel.UNKNOWN,
            None,
            None,
            "The AES key size or mode could not be proven statically, so the finding requires manual review.",
        )

    # ---------------------------------------------------------
    # 6. Fallback / Unrecognized Primitives (UNKNOWN)
    # ---------------------------------------------------------
    return (
        QuantumRiskLevel.UNKNOWN,
        None,
        None,
        f"Cryptographic algorithm '{raw_algo}' is unrecognized or insufficiently specified for automated quantum risk evaluation.",
    )


def build_reasoning(
    algorithm_name: str,
    quantum_risk: QuantumRiskLevel | str | None = None,
    key_size: int | str | None = None,
    mode: str | None = None,
) -> str:
    """Return a concise, single-sentence risk explanation for a cryptographic primitive."""
    del quantum_risk
    _, _, _, reasoning = evaluate_risk(
        algorithm_name=algorithm_name,
        key_size=key_size,
        mode=mode,
    )
    return reasoning


def enrich_finding_risk(finding: CryptoFinding) -> CryptoFinding:
    """Enrich a CryptoFinding instance with centralized quantum and classical risk evaluations.

    Risk Dimensions:
    - quantum_risk: Future quantum vulnerability (e.g. Shor's algorithm breaking RSA/ECC
      key exchange/signatures -> CRITICAL; Grover's algorithm halving symmetric bits -> MEDIUM/SAFE).
    - classical_risk: Current pre-quantum cryptographic strength (e.g. broken ciphers like
      MD5/DES/SHA-1 -> CRITICAL, deprecated key sizes like RSA-1024 -> MEDIUM, modern
      primitives like RSA-2048/AES-GCM -> SAFE).
    """
    algo = finding.algorithm_name
    key_size = finding.key_size
    mode = finding.mode

    quantum_risk, _cl_bits, _q_bits, reasoning = evaluate_risk(
        algorithm_name=algo,
        key_size=key_size,
        mode=mode,
    )

    # Derive classical risk (pre-quantum cryptographic strength):
    # - Classically broken primitives (MD5, SHA-1, DES, 3DES, ECB mode) -> CRITICAL.
    # - Shor-vulnerable asymmetric primitives (RSA, ECC, Diffie-Hellman):
    #   * Quantum exposure is CRITICAL (must migrate to PQC).
    #   * Classical risk is SAFE for modern parameters (e.g. RSA-2048, ECC P-256),
    #     or MEDIUM for deprecated key lengths (e.g. RSA <= 1024).
    # - Symmetric / PQC primitives with adequate key lengths -> SAFE.
    if is_classically_broken(algo, mode):
        classical_risk = QuantumRiskLevel.CRITICAL
    elif quantum_risk == QuantumRiskLevel.CRITICAL:
        if "1024" in algo or (isinstance(key_size, int) and key_size <= 1024 and "RSA" in algo.upper()):
            classical_risk = QuantumRiskLevel.MEDIUM
        else:
            classical_risk = QuantumRiskLevel.SAFE
    elif quantum_risk in (QuantumRiskLevel.MEDIUM, QuantumRiskLevel.SAFE):
        classical_risk = QuantumRiskLevel.SAFE
    else:
        classical_risk = QuantumRiskLevel.UNKNOWN

    nist_std = map_nist_standard(algo)

    # Do not replace a known, more specific scanner result with a less specific result
    if quantum_risk != QuantumRiskLevel.UNKNOWN or finding.quantum_risk == QuantumRiskLevel.UNKNOWN:
        object.__setattr__(finding, "quantum_risk", quantum_risk)

    if classical_risk != QuantumRiskLevel.UNKNOWN or finding.classical_risk == QuantumRiskLevel.UNKNOWN:
        object.__setattr__(finding, "classical_risk", classical_risk)

    if finding.evidence:
        for ev in finding.evidence:
            if not getattr(ev, "risk_reasoning", None):
                object.__setattr__(ev, "risk_reasoning", reasoning)
            if (
                not getattr(ev, "nist_standard", None)
                or ev.nist_standard == "none"
            ) and nist_std != "none":
                object.__setattr__(ev, "nist_standard", nist_std)

    return finding

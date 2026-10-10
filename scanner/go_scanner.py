"""Go-specific static analysis scanner for cryptographic primitives."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel
from scanner.utils import (
    SourcePatternRule,
    infer_key_size_from_literal,
    resolve_constant,
)


def resolve_go_constant(source_text: str, const_name: str) -> str:
    """Parse Go const and var declarations, returning value or 'unknown'."""
    return resolve_constant(source_text, const_name)


# Predefined pattern rules for reference and generic scanning
GO_RULES: list[SourcePatternRule] = [
    SourcePatternRule(
        rule_id="go-rsa-keygen",
        pattern=re.compile(r"\brsa\.GenerateKey\b"),
        algorithm_name="RSA",
        default_key_size="2048",
        risk_reasoning="RSA is vulnerable to Shor's quantum factoring algorithm.",
        nist_standard="FIPS 186-5",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-ed25519",
        pattern=re.compile(r"\bed25519\.(?:GenerateKey|Sign|Verify)\b"),
        algorithm_name="Ed25519",
        default_key_size="256",
        risk_reasoning="Ed25519 signature algorithm is broken by Shor's quantum algorithm.",
        nist_standard="FIPS 186-5",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-ecdsa",
        pattern=re.compile(r"\becdsa\.(?:GenerateKey|Sign|Verify)\b"),
        algorithm_name="ECDSA",
        default_key_size="256",
        risk_reasoning="ECDSA elliptic curve algorithm is vulnerable to Shor's quantum discrete-log algorithm.",
        nist_standard="FIPS 186-5",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-curve25519",
        pattern=re.compile(r"\bcurve25519\.(?:X25519|ScalarMult)\b"),
        algorithm_name="Curve25519",
        default_key_size="256",
        risk_reasoning="Curve25519 key exchange is vulnerable to Shor's quantum discrete-log algorithm.",
        nist_standard="SP 800-186",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-aes-cipher",
        pattern=re.compile(r"\baes\.NewCipher\b"),
        algorithm_name="AES-256-GCM",
        default_key_size="256",
        risk_reasoning="AES encryption analyzed for key size and mode security.",
        nist_standard="FIPS 197",
        risk_level=QuantumRiskLevel.SAFE,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-md5",
        pattern=re.compile(r"\bmd5\.(?:New|Sum)\b"),
        algorithm_name="MD5",
        default_key_size=None,
        risk_reasoning="MD5 is classically broken by collision attacks and weakened by Grover's algorithm.",
        nist_standard="none",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-sha1",
        pattern=re.compile(r"\bsha1\.(?:New|Sum)\b"),
        algorithm_name="SHA-1",
        default_key_size=None,
        risk_reasoning="SHA-1 is deprecated and vulnerable to collision attacks; weakened by Grover's algorithm.",
        nist_standard="FIPS 180-4",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-sha384",
        pattern=re.compile(r"\bsha512\.(?:Sum384|New384)\b"),
        algorithm_name="SHA-384",
        default_key_size=None,
        risk_reasoning="SHA-384 provides quantum-resistant collision and preimage security.",
        nist_standard="FIPS 180-4",
        risk_level=QuantumRiskLevel.SAFE,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-sha512",
        pattern=re.compile(r"\bsha512\.(?:Sum512|New)\b"),
        algorithm_name="SHA-512",
        default_key_size=None,
        risk_reasoning="SHA-512 provides 256 bits of quantum collision resistance against Grover's algorithm.",
        nist_standard="FIPS 180-4",
        risk_level=QuantumRiskLevel.SAFE,
        asset_type=AssetType.ALGORITHM,
    ),
    SourcePatternRule(
        rule_id="go-hmac",
        pattern=re.compile(r"\bhmac\.New\b"),
        algorithm_name="HMAC-SHA256",
        default_key_size=None,
        risk_reasoning="HMAC-SHA256 message authentication code is quantum-resistant against Grover's algorithm.",
        nist_standard="FIPS 198-1",
        risk_level=QuantumRiskLevel.SAFE,
        asset_type=AssetType.ALGORITHM,
    ),
]


def _strip_comments_and_strings(raw_lines: list[str]) -> list[str]:
    """Sanitize lines by stripping Go comments and string literals, preserving line count."""
    cleaned_lines: list[str] = []
    in_block_comment = False
    in_raw_string = False

    for line in raw_lines:
        cleaned_chars: list[str] = []
        i = 0
        n = len(line)
        in_string = False
        string_char = ""

        while i < n:
            if in_block_comment:
                if i + 1 < n and line[i:i + 2] == "*/":
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if in_raw_string:
                if line[i] == "`":
                    in_raw_string = False
                i += 1
                continue

            if in_string:
                if line[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if line[i] == string_char:
                    in_string = False
                i += 1
                continue

            if i + 1 < n and line[i:i + 2] == "/*":
                in_block_comment = True
                i += 2
                continue

            if i + 1 < n and line[i:i + 2] == "//":
                break

            if line[i] == "`":
                in_raw_string = True
                i += 1
                continue

            if line[i] in ('"', "'"):
                in_string = True
                string_char = line[i]
                i += 1
                continue

            cleaned_chars.append(line[i])
            i += 1

        cleaned_lines.append("".join(cleaned_chars))

    return cleaned_lines


def detect_custom_kdf(
    source_text: str,
    filepath: Path,
    base_dir: Path | None = None,
) -> list[CryptoFinding]:
    """Recognize hand-written PBKDF2 loops using HMAC-SHA256 (e.g., auth-gateway)."""
    findings: list[CryptoFinding] = []

    # Check for hand-written PBKDF2 pattern:
    # 1. deriveKey function or KDF loop
    # 2. hmac.New(sha256.New, ...)
    # 3. for ... iter loop with XORing (^=)
    is_pbkdf2_loop = (
        ("deriveKey" in source_text or "pbkdf2" in source_text.lower())
        and "hmac.New" in source_text
        and "sha256" in source_text
        and "^=" in source_text
    )

    if not is_pbkdf2_loop:
        return findings

    try:
        rel_path = filepath.relative_to(base_dir).as_posix() if base_dir else filepath.name
    except ValueError:
        rel_path = filepath.as_posix()

    lines = source_text.splitlines()
    target_line = 1
    target_snippet = "func deriveKey"

    for idx, line in enumerate(lines, start=1):
        if "func deriveKey" in line or "deriveKey(" in line:
            target_line = idx
            target_snippet = line.strip()
            break

    # Determine key length if iterations/keyLen const is present
    key_len_val = resolve_go_constant(source_text, "keyLen")
    key_size = 256
    if key_len_val.isdigit():
        bits = infer_key_size_from_literal(key_len_val)
        if bits.isdigit():
            key_size = int(bits)

    finding = CryptoFinding(
        algorithm_name="PBKDF2-HMAC-SHA256",
        asset_type=AssetType.ALGORITHM,
        source_type="source-code",
        key_size=key_size,
        crypto_function=CryptoFunction.KDF,
        quantum_risk=QuantumRiskLevel.SAFE,
        classical_risk=QuantumRiskLevel.SAFE,
        observation="observed",
        confidence="high",
        evidence=[
            Evidence(
                file_path=rel_path,
                line_number=target_line,
                matched_snippet=target_snippet,
                rule_id="go-custom-pbkdf2",
                risk_reasoning="Custom PBKDF2 key derivation function over HMAC-SHA256 maintains symmetric quantum resistance.",
                nist_standard="SP 800-132",
            )
        ],
    )
    findings.append(finding)
    return findings


def _resolve_aes_key_and_mode(
    source_text: str,
) -> tuple[int, str]:
    """Resolve key size in bits and cipher mode for AES in a Go file."""
    # 1. Resolve key size
    key_size = 256  # default
    found_size = False

    # Check var/const definitions for keys (e.g. exportKey, aesKey, keyLen)
    for m in re.finditer(r"\b(?:var|const)\s+([a-zA-Z0-9_]*[kK]ey[a-zA-Z0-9_]*)\b", source_text):
        var_name = m.group(1)
        resolved = resolve_go_constant(source_text, var_name)
        bits = infer_key_size_from_literal(resolved)
        if bits.isdigit():
            key_size = int(bits)
            found_size = True
            break

    # If not found yet, check make([]byte, keyLen) or make([]byte, 16/32)
    if not found_size:
        for m_make in re.finditer(r"\bmake\s*\(\s*\[\]byte\s*,\s*([a-zA-Z0-9_]+)\)", source_text):
            param = m_make.group(1)
            if param.isdigit() and int(param) in (16, 24, 32):
                key_size = int(param) * 8
                found_size = True
                break
            resolved = resolve_go_constant(source_text, param)
            bits = infer_key_size_from_literal(resolved)
            if bits.isdigit():
                key_size = int(bits)
                found_size = True
                break

    # 2. Resolve mode: Detect ECB mode if present; otherwise default or infer GCM
    mode = "GCM"
    if "block.Encrypt" in source_text and "cipher.NewGCM" not in source_text and "cipher.NewCBC" not in source_text:
        mode = "ECB"
    elif "cipher.NewCBC" in source_text:
        mode = "CBC"
    elif "cipher.NewCTR" in source_text:
        mode = "CTR"
    elif "cipher.NewGCM" in source_text:
        mode = "GCM"

    return key_size, mode


def scan_go_file(
    filepath: Path,
    base_dir: Path | None = None,
    rules: list[SourcePatternRule] | None = None,
) -> list[CryptoFinding]:
    """Scan a Go source file for cryptographic primitives."""
    filepath = Path(filepath)
    if not filepath.is_file():
        return []

    try:
        source_text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    try:
        rel_path = filepath.relative_to(base_dir).as_posix() if base_dir else filepath.name
    except ValueError:
        rel_path = filepath.as_posix()

    findings: list[CryptoFinding] = []
    raw_lines = source_text.splitlines()
    code_lines = _strip_comments_and_strings(raw_lines)

    if rules is not None:
        for idx, (raw_line, code_line) in enumerate(zip(raw_lines, code_lines), start=1):
            if not code_line.strip():
                continue
            for rule in rules:
                if rule.pattern.search(code_line):
                    findings.append(CryptoFinding(
                        algorithm_name=rule.algorithm_name,
                        asset_type=rule.asset_type,
                        source_type="source-code",
                        key_size=int(rule.default_key_size) if rule.default_key_size and rule.default_key_size.isdigit() else None,
                        quantum_risk=rule.risk_level,
                        observation="observed",
                        confidence="high",
                        evidence=[Evidence(
                            file_path=rel_path,
                            line_number=idx,
                            matched_snippet=raw_line.strip(),
                            rule_id=rule.rule_id,
                            risk_reasoning=rule.risk_reasoning,
                            nist_standard=rule.nist_standard,
                        )],
                    ))
        return findings

    # 1. Custom KDF (PBKDF2) detection
    custom_kdf_findings = detect_custom_kdf(source_text, filepath, base_dir=base_dir)
    findings.extend(custom_kdf_findings)

    # 2. Scan lines for cryptographic package usages
    for idx, (raw_line, code_line) in enumerate(zip(raw_lines, code_lines), start=1):
        if not code_line.strip():
            continue

        # A. RSA GenerateKey
        if "rsa.GenerateKey(" in code_line:
            size_m = re.search(r"rsa\.GenerateKey\s*\([^,]+,\s*([a-zA-Z0-9_]+)\)", code_line)
            key_size = 2048
            if size_m:
                val = size_m.group(1)
                if val.isdigit():
                    key_size = int(val)
                else:
                    resolved = resolve_go_constant(source_text, val)
                    if resolved.isdigit():
                        key_size = int(resolved)

            findings.append(CryptoFinding(
                algorithm_name=f"RSA-{key_size}",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=key_size,
                crypto_function=CryptoFunction.KEYGEN,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-rsa-keygen",
                    risk_reasoning="RSA is vulnerable to Shor's quantum factoring algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))

        # B. RSA Sign / Verify
        elif "rsa.SignPKCS1v15(" in code_line or "rsa.SignPSS(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="RSA",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.SIGN,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-rsa-sign",
                    risk_reasoning="RSA is vulnerable to Shor's quantum factoring algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))
        elif "rsa.VerifyPKCS1v15(" in code_line or "rsa.VerifyPSS(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="RSA",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.VERIFY,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-rsa-verify",
                    risk_reasoning="RSA is vulnerable to Shor's quantum factoring algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))

        # C. Ed25519
        if "ed25519.GenerateKey(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="Ed25519",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=256,
                crypto_function=CryptoFunction.KEYGEN,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-ed25519-keygen",
                    risk_reasoning="Ed25519 signature algorithm is broken by Shor's quantum algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))
        elif "ed25519.Sign(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="Ed25519",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=256,
                crypto_function=CryptoFunction.SIGN,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-ed25519-sign",
                    risk_reasoning="Ed25519 signature algorithm is broken by Shor's quantum algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))
        elif "ed25519.Verify(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="Ed25519",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=256,
                crypto_function=CryptoFunction.VERIFY,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-ed25519-verify",
                    risk_reasoning="Ed25519 signature algorithm is broken by Shor's quantum algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))

        # D. ECDSA
        if "ecdsa.GenerateKey(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="ECDSA",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=256,
                crypto_function=CryptoFunction.KEYGEN,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-ecdsa-keygen",
                    risk_reasoning="ECDSA elliptic curve algorithm is vulnerable to Shor's quantum discrete-log algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))
        elif "ecdsa.Sign(" in code_line or "ecdsa.SignASN1(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="ECDSA",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.SIGN,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-ecdsa-sign",
                    risk_reasoning="ECDSA elliptic curve algorithm is vulnerable to Shor's quantum discrete-log algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))
        elif "ecdsa.Verify(" in code_line or "ecdsa.VerifyASN1(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="ECDSA",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.VERIFY,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-ecdsa-verify",
                    risk_reasoning="ECDSA elliptic curve algorithm is vulnerable to Shor's quantum discrete-log algorithm.",
                    nist_standard="FIPS 186-5",
                )],
            ))

        # E. Curve25519
        if "curve25519.X25519(" in code_line or "curve25519.ScalarMult(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="Curve25519",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=256,
                crypto_function=CryptoFunction.KEY_EXCHANGE,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-curve25519",
                    risk_reasoning="Curve25519 key exchange is vulnerable to Shor's quantum discrete-log algorithm.",
                    nist_standard="SP 800-186",
                )],
            ))

        # F. AES
        if "aes.NewCipher(" in code_line:
            key_size, mode = _resolve_aes_key_and_mode(source_text)
            if mode == "ECB":
                quantum_risk = QuantumRiskLevel.CRITICAL
                risk_reasoning = "AES in ECB mode lacks semantic security and is classically broken; pattern leakage occurs."
            elif key_size == 128:
                quantum_risk = QuantumRiskLevel.MEDIUM
                risk_reasoning = "AES-128 is weakened by Grover's algorithm to 64-bit security."
            else:
                quantum_risk = QuantumRiskLevel.SAFE
                risk_reasoning = "AES-256 provides 128-bit quantum security against Grover's algorithm."

            findings.append(CryptoFinding(
                algorithm_name=f"AES-{key_size}-{mode}",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=key_size,
                mode=mode,
                crypto_function=CryptoFunction.ENCRYPT,
                quantum_risk=quantum_risk,
                classical_risk=QuantumRiskLevel.CRITICAL if mode == "ECB" else QuantumRiskLevel.SAFE,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-aes-128-ecb" if mode == "ECB" else "go-aes-cipher",
                    risk_reasoning=risk_reasoning,
                    nist_standard="SP 800-38A" if mode == "ECB" else ("SP 800-38D" if mode == "GCM" else "FIPS 197"),
                )],
            ))

        # G. DES / 3DES
        if "des.NewCipher(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="DES",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=56,
                crypto_function=CryptoFunction.ENCRYPT,
                quantum_risk=QuantumRiskLevel.MEDIUM,
                classical_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-des",
                    risk_reasoning="DES is classically broken by brute force and carries inadequate key length.",
                    nist_standard="none",
                )],
            ))
        elif "des.NewTripleDESCipher(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="3DES",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                key_size=168,
                crypto_function=CryptoFunction.ENCRYPT,
                quantum_risk=QuantumRiskLevel.MEDIUM,
                classical_risk=QuantumRiskLevel.MEDIUM,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-3des",
                    risk_reasoning="3DES is deprecated and vulnerable to Sweet32 collision attacks.",
                    nist_standard="SP 800-67",
                )],
            ))

        # H. MD5
        if "md5.Sum(" in code_line or "md5.New(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="MD5",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.DIGEST,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                classical_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-md5",
                    risk_reasoning="MD5 is classically broken by collision attacks and weakened by Grover's algorithm.",
                    nist_standard="none",
                )],
            ))

        # I. SHA-1
        if "sha1.Sum(" in code_line or "sha1.New(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="SHA-1",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.DIGEST,
                quantum_risk=QuantumRiskLevel.CRITICAL,
                classical_risk=QuantumRiskLevel.CRITICAL,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-sha1",
                    risk_reasoning="SHA-1 is deprecated and vulnerable to collision attacks; weakened by Grover's algorithm.",
                    nist_standard="FIPS 180-4",
                )],
            ))

        # J. SHA-384 and SHA-512
        if "sha512.Sum384(" in code_line or "sha512.New384(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="SHA-384",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.DIGEST,
                quantum_risk=QuantumRiskLevel.SAFE,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-sha384",
                    risk_reasoning="SHA-384 provides quantum-resistant collision and preimage security.",
                    nist_standard="FIPS 180-4",
                )],
            ))
        elif "sha512.Sum512(" in code_line or "sha512.New(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="SHA-512",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.DIGEST,
                quantum_risk=QuantumRiskLevel.SAFE,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-sha512",
                    risk_reasoning="SHA-512 provides 256 bits of quantum collision resistance against Grover's algorithm.",
                    nist_standard="FIPS 180-4",
                )],
            ))

        # K. HMAC-SHA256
        if "hmac.New(" in code_line:
            findings.append(CryptoFinding(
                algorithm_name="HMAC-SHA256",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.MAC,
                quantum_risk=QuantumRiskLevel.SAFE,
                classical_risk=QuantumRiskLevel.SAFE,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-hmac-sha256",
                    risk_reasoning="HMAC-SHA256 message authentication code is quantum-resistant against Grover's algorithm.",
                    nist_standard="FIPS 198-1",
                )],
            ))
        # Standalone SHA-256 (not inside hmac.New)
        elif "sha256.Sum256(" in code_line or ("sha256.New(" in code_line and "hmac" not in code_line):
            findings.append(CryptoFinding(
                algorithm_name="SHA-256",
                asset_type=AssetType.ALGORITHM,
                source_type="source-code",
                crypto_function=CryptoFunction.DIGEST,
                quantum_risk=QuantumRiskLevel.SAFE,
                observation="observed",
                confidence="high",
                evidence=[Evidence(
                    file_path=rel_path,
                    line_number=idx,
                    matched_snippet=raw_line.strip(),
                    rule_id="go-sha256",
                    risk_reasoning="SHA-256 provides 128 bits of quantum security against Grover's algorithm.",
                    nist_standard="FIPS 180-4",
                )],
            ))

    return findings


def scan(path: Path) -> list[CryptoFinding]:
    """Protocol-compliant scan method for directories or Go files."""
    path = Path(path)
    if path.is_file():
        return scan_go_file(path)
    if path.is_dir():
        findings: list[CryptoFinding] = []
        for p in sorted(path.rglob("*.go")):
            if p.is_file():
                findings.extend(scan_go_file(p, base_dir=path))
        return findings
    return []

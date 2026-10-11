"""Limited discovery when optional scanners are unavailable.

These heuristics do not parse complete source languages or network packets.
They produce low-confidence observations, never their own risk assessments.
Cloud fallback does not resolve AWS policies or region-dependent defaults.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence


def _finding(path: Path, name: str, source: Literal["source-code", "cloud-posture", "network-capture"], evidence: Evidence, **parameters: Any) -> CryptoFinding:
    finding = CryptoFinding(
        algorithm_name=name, source_type=source,
        observation="configured" if source == "cloud-posture" else "observed",
        confidence="low", evidence=[evidence], **parameters,
    )
    object.__setattr__(finding, "_scanner_source", "FALLBACK heuristic")
    return finding


def scan_source_file(path: Path) -> list[CryptoFinding]:
    """Recognise a few explicit API calls without assuming key sizes or modes."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings = []
    # Full-line comments are ignored. This is not a complete language parser.
    for index, raw in enumerate(content.splitlines(), start=1):
        if raw.lstrip().startswith(("#", "//", "/*", "*")):
            continue
        line = re.sub(r"\s+(?:#|//).*$", "", raw)
        detected: list[tuple[str, CryptoFunction, dict[str, Any], str]] = []
        if re.search(r'\brsa\.(?:generate_private_key|GenerateKey)\s*\(|KeyPairGenerator\.getInstance\s*\(\s*"RSA"', line):
            # Only recognised size argument positions count as observed sizes.
            size = re.search(r"key_size\s*=\s*([1-9]\d*)\b", line)
            if size is None:
                size = re.search(r"rsa\.(?:GenerateKey|generate_private_key)\s*\([^,]+,\s*([1-9]\d*)\s*\)", line)
            bits = int(size.group(1)) if size else None
            detected.append(("RSA", CryptoFunction.KEYGEN, {"key_size": bits}, "src-rsa-keygen"))
        for api, operation in (("GenerateKey", CryptoFunction.KEYGEN), ("Sign", CryptoFunction.SIGN), ("Verify", CryptoFunction.VERIFY)):
            if re.search(rf"\bed25519\.{api}\s*\(", line):
                detected.append(("Ed25519", operation, {}, "src-ed25519"))
        for name, pattern in (
            ("MD5", r'\b(?:hashlib\.md5|md5\.(?:New|Sum))\s*\(|MessageDigest\.getInstance\s*\(\s*"MD5"'),
            ("SHA-1", r'\b(?:hashlib\.sha1|sha1\.(?:New|Sum))\s*\(|MessageDigest\.getInstance\s*\(\s*"SHA-?1"'),
        ):
            if re.search(pattern, line, re.IGNORECASE):
                detected.append((name, CryptoFunction.DIGEST, {}, "src-hash-digest"))
        if re.search(r'algorithms\.AES\s*\(|aes\.NewCipher\s*\(|Cipher\.getInstance\s*\(\s*"AES', line):
            # A Java transformation identifies a mode but not a key length.
            mode = re.search(r'Cipher\.getInstance\s*\(\s*"AES/(ECB|CBC|GCM|CTR|CFB|OFB)/', line)
            detected.append(("AES", CryptoFunction.UNKNOWN, {"mode": mode.group(1) if mode else None}, "src-aes-cipher"))
        if re.search(r"\b(?:PBKDF2|pbkdf2_hmac)\s*\(|SecretKeyFactory\.getInstance\s*\(\s*\"PBKDF2", line):
            detected.append(("PBKDF2", CryptoFunction.KDF, {}, "src-pbkdf2-kdf"))
        for name, operation, parameters, rule in detected:
            findings.append(_finding(path, name, "source-code", Evidence(
                file_path=path.name, line_number=index, matched_snippet=raw.strip(),
                rule_id=rule, risk_reasoning="Limited API heuristic; unresolved parameters require the full scanner.",
            ), crypto_function=operation, **parameters))
    return findings


def _cloud_key(name: object) -> tuple[str, int | None]:
    """Only explicit exported specifications identify key parameters."""
    if not isinstance(name, str) or not name.strip():
        return "unknown", None
    rsa = re.fullmatch(r"RSA_(2048|3072|4096)", name)
    if rsa:
        return "RSA", int(rsa.group(1))
    ec = re.fullmatch(r"(?:ECC_NIST_P|EC_prime)(256|384|521)(?:v1)?", name)
    if ec:
        return "EC", int(ec.group(1))
    if name == "EC_secp384r1":
        return "EC", 384
    if name == "EC_secp521r1":
        return "EC", 521
    return name, None


def scan_cloud_file(path: Path) -> list[CryptoFinding]:
    """Preserve exported resources; omit policy expansion and inferred defaults."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    findings = []

    def resources(parent, field):
        items = parent.get(field, [])
        return enumerate(items) if isinstance(items, list) else []

    def add(name, resource, location, rule, **parameters):
        findings.append(_finding(path, name, "cloud-posture", Evidence(
            file_path=path.name, json_path=location, rule_id=rule,
            matched_snippet=json.dumps(resource, ensure_ascii=False),
            risk_reasoning="Limited inventory heuristic; policy contents and contextual defaults are not resolved.",
        ), **parameters))

    for index, key in resources(data, "Keys"):
        if isinstance(key, dict):
            name, bits = _cloud_key(key.get("KeySpec"))
            add(name, key, f"$.Keys[{index}]", "fallback-kms-key", key_size=bits, asset_type=AssetType.KEY)
    for index, cert in resources(data, "Certificates"):
        if isinstance(cert, dict):
            name, bits = _cloud_key(cert.get("KeyAlgorithm"))
            location = f"$.Certificates[{index}]"
            add(name, cert, location, "fallback-acm-key", key_size=bits, asset_type=AssetType.CERTIFICATE)
            signature = cert.get("SignatureAlgorithm")
            if isinstance(signature, str) and signature.strip():
                add(signature, cert, location + ".SignatureAlgorithm", "fallback-acm-signature", crypto_function=CryptoFunction.SIGN)
    for lb_index, lb in resources(data, "LoadBalancers"):
        if isinstance(lb, dict):
            for listener_index, listener in resources(lb, "Listeners"):
                if isinstance(listener, dict):
                    protocol = listener.get("Protocol")
                    name = protocol if isinstance(protocol, str) and protocol.strip() else "unknown"
                    add(name, listener, f"$.LoadBalancers[{lb_index}].Listeners[{listener_index}]",
                        "fallback-elb-listener", asset_type=AssetType.PROTOCOL)
    return findings


def scan_pcap_file(path: Path) -> list[CryptoFinding]:
    """Byte markers are hints only: no negotiated suite, packet index or version."""
    try:
        content = path.read_bytes()
    except OSError:
        return []
    findings = []
    for name, present in (
        ("HTTP", any(marker in content for marker in (b"HTTP/", b"GET ", b"POST "))),
        ("TLS", b"\x16\x03" in content or b"TLS" in content),
    ):
        if present:
            findings.append(_finding(path, name, "network-capture", Evidence(
                file_path=path.name, rule_id="fallback-network-marker",
                matched_snippet=f"{name} byte marker",
                risk_reasoning="Byte marker only; packet parsing is required to confirm protocol and negotiation.",
            ), asset_type=AssetType.PROTOCOL))
    return findings

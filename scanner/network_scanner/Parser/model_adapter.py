"""Convert packet metadata into the shared, validated finding contract.

Risk assessment is a subsequent pipeline step: model defaults remain UNKNOWN.
Protocol proposals are not evidence that an algorithm was negotiated.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence
from scanner.network_scanner.algorithm_mapper import (
    CIPHER_SUITES, GROUPS, SIGNATURE_SCHEMES, Observation, Primitive,
    cipher_primitives, identifier_label, is_grease, parse_identifier,
)


_CONTEXT_FIELDS = (
    "packet_number", "stream_id", "timestamp", "source_ip", "destination_ip",
    "source_port", "destination_port", "server_name", "handshake_type",
    "tls_version", "protocol_banner", "is_server", "role_source",
    "protocol", "http_method", "http_host",
)


def _values(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return [str(item) for item in values if item is not None and str(item).strip()]


def _unique_identifiers(values: list[str]) -> list[str]:
    seen: set[int | str] = set()
    result = []
    for value in values:
        identifier = parse_identifier(value)
        key = identifier if identifier is not None else value
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _finding(path: Path, entry: dict, primitive: Primitive, observation: Observation,
             rule_id: str, protocol: str | None, *,
             asset_type: AssetType = AssetType.ALGORITHM,
             context: dict | None = None) -> CryptoFinding:
    details = {key: entry[key] for key in _CONTEXT_FIELDS if entry.get(key) is not None}
    details.update(context or {})
    raw_packet = entry.get("packet_number")
    try:
        packet = int(raw_packet) if raw_packet is not None and not isinstance(raw_packet, bool) else None
    except (ValueError, TypeError):
        packet = None
    if packet is not None and packet < 1:
        packet = None
    evidence = Evidence(
        file_path=str(path), packet_number=packet, rule_id=rule_id,
        matched_snippet=json.dumps(details, ensure_ascii=False, sort_keys=True),
    )
    return CryptoFinding(
        algorithm_name=primitive.algorithm_name, asset_type=asset_type,
        source_type="network-capture", key_size=primitive.key_size,
        mode=primitive.mode, padding=primitive.padding, protocol=protocol,
        crypto_function=primitive.crypto_function, observation=observation,
        confidence="high", evidence=[evidence],
    )


def _tls_findings(entries: list[dict], path: Path) -> list[CryptoFinding]:
    findings = []
    for entry in entries:
        hello = entry.get("handshake_type")
        if hello not in {"Client Hello", "Server Hello"} or entry.get("hello_retry_request"):
            continue
        client = hello == "Client Hello"
        observation = "advertised" if client else "negotiated"
        protocol = entry.get("tls_version")
        versions = _values(entry.get("supported_versions")) if client else []
        versions = versions or _values(protocol)
        for version in dict.fromkeys(versions):
            findings.append(_finding(
                path, entry, Primitive(version, CryptoFunction.UNKNOWN), observation,
                "NETWORK-TLS-VERSION", version, asset_type=AssetType.PROTOCOL,
            ))
        ciphers = _values(entry.get("cipher_suites") if client else entry.get("selected_cipher"))
        for value in _unique_identifiers(ciphers):
            identifier = parse_identifier(value)
            # GREASE and SCSV are negotiation markers, not cryptographic primitives.
            if is_grease(identifier) or identifier in {0x00FF, 0x5600}:
                continue
            suite = CIPHER_SUITES.get(identifier)
            context = {"cipher_suite": identifier_label(value)}
            if suite is None:
                primitives = [Primitive(f"TLS-CIPHER-{identifier_label(value)}", CryptoFunction.UNKNOWN)]
            else:
                context["cipher_suite_name"] = suite.name
                primitives = cipher_primitives(suite, protocol)
            for primitive in primitives:
                # In older suites, the suffix names a keyed MAC/PRF. Do not
                # report that alone as evidence of a standalone digest use.
                if suite is not None and not suite.tls13 and primitive.crypto_function == CryptoFunction.DIGEST:
                    continue
                findings.append(_finding(path, entry, primitive, observation,
                                         "NETWORK-TLS-CIPHER", protocol, context=context))
        groups = (_values(entry.get("supported_groups")) + _values(entry.get("key_share_groups"))
                  if client else _values(entry.get("selected_group")))
        for value in _unique_identifiers(groups):
            identifier = parse_identifier(value)
            if is_grease(identifier):
                continue
            primitive = GROUPS.get(identifier) or Primitive(
                f"TLS-GROUP-{identifier_label(value)}", CryptoFunction.KEY_EXCHANGE)
            findings.append(_finding(path, entry, primitive, observation,
                                     "NETWORK-TLS-GROUP", protocol,
                                     context={"group": identifier_label(value)}))
        # Signature algorithms in ClientHello are capabilities, not proof of
        # the signature or certificate used by the server.
        schemes = _values(entry.get("signature_algorithms")) if client else []
        for value in _unique_identifiers(schemes):
            identifier = parse_identifier(value)
            if is_grease(identifier):
                continue
            primitives = SIGNATURE_SCHEMES.get(identifier) or (
                Primitive(f"TLS-SIGNATURE-{identifier_label(value)}", CryptoFunction.SIGN),)
            for primitive in primitives:
                findings.append(_finding(path, entry, primitive, "advertised",
                                         "NETWORK-TLS-SIGNATURE", protocol,
                                         context={"signature_scheme": identifier_label(value)}))
    return findings


_SSH_KEX = {
    "curve25519-sha256": Primitive("ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255),
    "curve25519-sha256@libssh.org": Primitive("ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255),
    "ecdh-sha2-nistp256": Primitive("ECDHE-secp256r1", CryptoFunction.KEY_EXCHANGE, 256),
    "ecdh-sha2-nistp384": Primitive("ECDHE-secp384r1", CryptoFunction.KEY_EXCHANGE, 384),
    "ecdh-sha2-nistp521": Primitive("ECDHE-secp521r1", CryptoFunction.KEY_EXCHANGE, 521),
    "diffie-hellman-group1-sha1": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 1024),
    "diffie-hellman-group14-sha1": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 2048),
    "diffie-hellman-group14-sha256": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 2048),
    "diffie-hellman-group16-sha512": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 4096),
    "diffie-hellman-group18-sha512": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 8192),
    "diffie-hellman-group-exchange-sha1": Primitive("DHE", CryptoFunction.KEY_EXCHANGE),
    "diffie-hellman-group-exchange-sha256": Primitive("DHE", CryptoFunction.KEY_EXCHANGE),
    "mlkem768x25519-sha256": Primitive("MLKEM768X25519", CryptoFunction.KEY_EXCHANGE),
    "sntrup761x25519-sha512": Primitive("SNTRUP761X25519", CryptoFunction.KEY_EXCHANGE),
    "sntrup761x25519-sha512@openssh.com": Primitive("SNTRUP761X25519", CryptoFunction.KEY_EXCHANGE),
}
_SSH_HOST = {
    name: Primitive("RSA", CryptoFunction.SIGN, padding="PKCS1v15")
    for name in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512")
}
_SSH_HOST.update({
    "ssh-dss": Primitive("DSA", CryptoFunction.SIGN),
    "ssh-ed25519": Primitive("Ed25519", CryptoFunction.SIGN, 255),
    **{name: Primitive("ECDSA", CryptoFunction.SIGN, bits)
       for name, bits in (("ecdsa-sha2-nistp256", 256), ("ecdsa-sha2-nistp384", 384),
                          ("ecdsa-sha2-nistp521", 521))},
})
_SSH_CIPHERS = {
    f"aes{bits}-{mode}": Primitive("AES", CryptoFunction.ENCRYPT, bits, mode.upper())
    for bits in (128, 192, 256) for mode in ("cbc", "ctr")
}
_SSH_CIPHERS.update({
    **{f"aes{bits}-gcm@openssh.com": Primitive("AES", CryptoFunction.ENCRYPT, bits, "GCM")
       for bits in (128, 256)},
    "3des-cbc": Primitive("3DES", CryptoFunction.ENCRYPT, 168, "CBC"),
    # 256 describes the underlying ChaCha key, not all SSH keying material.
    "chacha20-poly1305@openssh.com": Primitive("ChaCha20-Poly1305", CryptoFunction.ENCRYPT, 256),
    "none": Primitive("NULL", CryptoFunction.ENCRYPT),
})
_SSH_MACS = {
    wire + suffix: Primitive(name, CryptoFunction.MAC)
    for wire, name in (("hmac-sha1", "HMAC-SHA-1"), ("hmac-sha2-256", "HMAC-SHA-256"),
                       ("hmac-sha2-512", "HMAC-SHA-512"), ("hmac-md5", "HMAC-MD5"))
    for suffix in ("", "-etm@openssh.com")
}
_SSH_FIELDS = (
    ("kex_algorithms", _SSH_KEX, CryptoFunction.KEY_EXCHANGE),
    ("server_host_key_algorithms", _SSH_HOST, CryptoFunction.SIGN),
    ("encryption_client_to_server", _SSH_CIPHERS, CryptoFunction.ENCRYPT),
    ("encryption_server_to_client", _SSH_CIPHERS, CryptoFunction.ENCRYPT),
    ("mac_client_to_server", _SSH_MACS, CryptoFunction.MAC),
    ("mac_server_to_client", _SSH_MACS, CryptoFunction.MAC),
)
_SSH_MARKERS = {"ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"}


def _ssh_findings(entries: list[dict], path: Path) -> list[CryptoFinding]:
    findings = []
    for entry in entries:
        banner = entry.get("protocol_banner")
        version = re.match(r"SSH-(\d+\.\d+)-", banner) if banner else None
        protocol = f"SSH {version.group(1)}" if version else "SSH"
        if banner:
            findings.append(_finding(path, entry, Primitive("SSH", CryptoFunction.UNKNOWN),
                                     "observed", "NETWORK-SSH-BANNER", protocol,
                                     asset_type=AssetType.PROTOCOL))
        for field, registry, function in _SSH_FIELDS:
            values = [name.strip() for item in _values(entry.get(field))
                      for name in item.split(",") if name.strip()]
            for value in dict.fromkeys(values):
                if field == "kex_algorithms" and value in _SSH_MARKERS:
                    continue
                primitive = registry.get(value) or Primitive(value, function)
                findings.append(_finding(path, entry, primitive, "advertised",
                                         "NETWORK-SSH-ALGORITHM", protocol,
                                         context={"ssh_field": field, "ssh_algorithm": value}))
    return findings


def findings_from_metadata(metadata: dict, path: Path) -> list[CryptoFinding]:
    """Normalize raw results into validated assets with packet evidence."""
    findings = _tls_findings(metadata.get("tls_sessions", []), path)
    findings.extend(_ssh_findings(metadata.get("ssh_sessions", []), path))
    for entry in metadata.get("cleartext_traffic", []):
        protocol = entry.get("protocol")
        if protocol:
            findings.append(_finding(path, entry, Primitive("Cleartext", CryptoFunction.UNKNOWN),
                                     "observed", "NETWORK-CLEARTEXT", protocol,
                                     asset_type=AssetType.PROTOCOL))
    return findings

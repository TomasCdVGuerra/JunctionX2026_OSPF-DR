"""Convert packet metadata into the shared, validated finding contract.

Risk assessment is a subsequent pipeline step: model defaults remain UNKNOWN.
Protocol proposals are not evidence that an algorithm was negotiated.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence
from scanner.network_scanner.algorithm_mapper import (
    CIPHER_SUITES,
    GROUPS,
    SIGNATURE_SCHEMES,
    SSH_FIELDS,
    SSH_MARKERS,
    CipherSuiteVersionError,
    Observation,
    Primitive,
    cipher_primitives,
    identifier_label,
    is_grease,
    network_context,
    parse_identifier,
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
    details = network_context({**entry, **(context or {})})
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
    details.pop("packet_number", None)
    if packet is not None:
        details["packet_number"] = packet
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
        observation: Observation = "advertised" if client else "negotiated"
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
            if identifier is None or is_grease(identifier) or identifier in {0x00FF, 0x5600}:
                continue
            suite = CIPHER_SUITES.get(identifier)
            context = {"cipher_suite": identifier_label(value)}
            if suite is None:
                primitives = [Primitive(f"TLS-CIPHER-{identifier_label(value)}", CryptoFunction.UNKNOWN)]
            else:
                context["cipher_suite_name"] = suite.name
                mapping_version = protocol
                if client:
                    # Proposals can include suites from different TLS versions.
                    mapping_version = ("TLS 1.3" if suite.tls13 else
                                       protocol if protocol in {"SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"} else None)
                try:
                    primitives = cipher_primitives(suite, mapping_version)
                except CipherSuiteVersionError:
                    context["mapping_status"] = "incompatible-version"
                    primitives = [Primitive(f"TLS-CIPHER-{identifier_label(value)}", CryptoFunction.UNKNOWN)]
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
            # Preserve unmapped textual identifiers as unresolved evidence.
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
            if identifier is None or is_grease(identifier):
                continue
            primitives = list(SIGNATURE_SCHEMES.get(identifier) or (
                Primitive(f"TLS-SIGNATURE-{identifier_label(value)}", CryptoFunction.SIGN),))
            for primitive in primitives:
                findings.append(_finding(path, entry, primitive, "advertised",
                                         "NETWORK-TLS-SIGNATURE", protocol,
                                         context={"signature_scheme": identifier_label(value)}))
    return findings


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
        for field, registry, function in SSH_FIELDS:
            values = [name.strip() for item in _values(entry.get(field))
                      for name in item.split(",") if name.strip()]
            for value in dict.fromkeys(values):
                if field == "kex_algorithms" and value in SSH_MARKERS:
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

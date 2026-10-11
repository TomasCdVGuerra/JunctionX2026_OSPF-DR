"""Assess SSH offers and infer selections only for unambiguous peer pairs.

Client preference follows RFC 4253 section 7.1. OpenSSH AEAD ciphers supply
their own authentication, so their MAC proposals remain advertised.
"""
from __future__ import annotations

import json
from pathlib import Path

from scanner.models import CryptoFinding, QuantumRiskLevel
from scanner.network_scanner.algorithm_mapper import SSH_CIPHERS, SSH_FIELDS
from scanner.network_scanner.analyser.risk_assessment import enrich_finding
from scanner.network_scanner.model_adapter import findings_from_metadata


_UNKNOWN_SSH_ALGORITHM = (
    QuantumRiskLevel.UNKNOWN,
    QuantumRiskLevel.UNKNOWN,
    "The SSH wire algorithm has no verified mapping for this negotiation "
    "field; quantum and classical risk remain unknown.",
    "Resolve the SSH wire identifier and review its cryptographic "
    "parameters before assessing risk.",
)


def _endpoint(entry: dict, direction: str) -> tuple[str, str] | None:
    """Require a complete endpoint and normalize the port representation."""
    address = entry.get(f"{direction}_ip")
    port = entry.get(f"{direction}_port")
    if not isinstance(address, str) or not address.strip():
        return None
    if isinstance(port, bool) or not isinstance(port, (str, int)):
        return None
    normalized_port = str(port).strip()
    if not normalized_port.isdecimal() or not 1 <= int(normalized_port) <= 65535:
        return None
    return address.strip(), str(int(normalized_port))


def _opposite_endpoints(client: dict, server: dict) -> bool:
    client_source = _endpoint(client, "source")
    client_destination = _endpoint(client, "destination")
    return (
        client_source is not None
        and client_destination is not None
        and client_source == _endpoint(server, "destination")
        and client_destination == _endpoint(server, "source")
    )


def _is_aead(wire_name: str) -> bool:
    primitive = SSH_CIPHERS[wire_name]
    return primitive.mode == "GCM" or primitive.algorithm_name == "ChaCha20-Poly1305"


def analyze_ssh(entries: list[dict], path: Path) -> list[CryptoFinding]:
    """Assess SSH metadata while preserving advertised and observed evidence.

    A selection is inferred only when a stream contains exactly one offer
    from each explicit role and their complete endpoints are reversed.
    Additional offers, including ambiguous rekeys or retransmissions, are
    kept advertised because the metadata cannot identify exchange rounds.
    Disjoint required lists prevent every inferred selection for that pair.
    Banner-only entries do not count as algorithm offers. Missing algorithms
    or host-key requirements prevent a complete handshake assessment.

    The selected findings have medium confidence: KEXINIT preferences do
    not establish NEWKEYS, authentication, or handshake completion.
    """
    findings: list[CryptoFinding] = []
    streams: dict[str, list[tuple[dict, dict[str, dict[str, CryptoFinding]]]]] = {}
    registries = {field: registry for field, registry, _ in SSH_FIELDS}

    for entry in entries:
        observations = findings_from_metadata({"ssh_sessions": [entry]}, path)

        # The adapter already splits CSV lists, deduplicates names and excludes
        # negotiation markers. Its evidence retains the original wire names.
        offered: dict[str, dict[str, CryptoFinding]] = {}
        for finding in observations:
            if finding.observation == "advertised":
                context = json.loads(finding.evidence[0].matched_snippet)
                field, name = context["ssh_field"], context["ssh_algorithm"]
                # A wire name resembling a canonical primitive is still
                # unknown unless this SSH field has an exact verified mapping.
                override = None if name in registries[field] else _UNKNOWN_SSH_ALGORITHM
                assessed = enrich_finding(finding, risk_override=override)
                offered.setdefault(field, {})[name] = assessed
            else:
                assessed = enrich_finding(finding)
            findings.append(assessed)

        if not any(entry.get(field) for field, _, _ in SSH_FIELDS):
            continue
        stream = entry.get("stream_id")
        if isinstance(stream, bool) or not isinstance(stream, (str, int)) or not str(stream).strip():
            continue
        streams.setdefault(str(stream).strip(), []).append((entry, offered))

    for offers in streams.values():
        # Without round identifiers, picking from several messages would join
        # unrelated exchanges. Require one offer from each peer for the stream.
        if len(offers) != 2:
            continue
        clients = [offer for offer in offers if offer[0].get("is_server") is False]
        servers = [offer for offer in offers if offer[0].get("is_server") is True]
        if len(clients) != 1 or len(servers) != 1:
            continue
        client_entry, client_algorithms = clients[0]
        server_entry, server_algorithms = servers[0]
        if not _opposite_endpoints(client_entry, server_entry):
            continue

        selections: dict[str, str] = {}
        for field, _, _ in SSH_FIELDS:
            server_names = server_algorithms.get(field, {})
            for name in client_algorithms.get(field, {}):
                if name in server_names:
                    selections[field] = name
                    break

        # RFC 4253 section 7.1 requires disconnect when a required list has
        # no common choice. A common cipher alone cannot establish selection
        # when, for example, the peers have incompatible key exchanges.
        required_fields = {
            "kex_algorithms", "server_host_key_algorithms",
            "encryption_client_to_server", "encryption_server_to_client",
        }
        for direction in ("client_to_server", "server_to_client"):
            cipher = selections.get(f"encryption_{direction}")
            if cipher in SSH_CIPHERS and not _is_aead(cipher):
                required_fields.add(f"mac_{direction}")
        if any(client_entry.get(field) and server_entry.get(field) and field not in selections
               for field in required_fields):
            continue

        for field, name in selections.items():
            if field.startswith("mac_"):
                cipher = selections.get(field.replace("mac_", "encryption_", 1))
                if cipher is None or cipher not in SSH_CIPHERS or _is_aead(cipher):
                    continue

            selected = client_algorithms[field][name].model_copy(deep=True)
            selected.observation = "negotiated"
            selected.confidence = "medium"
            selected.evidence.extend(
                evidence.model_copy(deep=True)
                for evidence in server_algorithms[field][name].evidence
            )
            for evidence in selected.evidence:
                evidence.risk_reasoning += (
                    " Selection is inferred from both SSH offers using client "
                    "preference; completion is not established."
                )
            findings.append(selected)

    return findings

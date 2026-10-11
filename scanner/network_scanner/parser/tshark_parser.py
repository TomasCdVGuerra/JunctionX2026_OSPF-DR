"""Offline network metadata extraction using TShark.

Decoded protocol fields provide evidence; a TCP port alone cannot prove
cleartext traffic. TLS capabilities and negotiated selections stay separate.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from scanner.models import CryptoFinding
from scanner.network_scanner.algorithm_mapper import is_grease, parse_identifier
from scanner.network_scanner.model_adapter import findings_from_metadata

logger = logging.getLogger(__name__)


class PcapParserError(Exception):
    """An input capture or the TShark process could not be read."""


def find_tshark_binary() -> str:
    """Find TShark in TSHARK_PATH, PATH, or its usual installation folder."""
    configured = os.environ.get("TSHARK_PATH")
    if configured:
        candidate = shutil.which(configured) or configured
        if Path(candidate).is_file():
            return str(candidate)
        raise PcapParserError(f"TSHARK_PATH não aponta para um executável: {configured}")
    binary = shutil.which("tshark")
    if binary:
        return binary
    candidates = [Path("/Applications/Wireshark.app/Contents/MacOS/tshark")]
    if os.name == "nt":
        for directory in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                          os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidates.append(Path(directory) / "Wireshark" / "tshark.exe")
    for c_path in candidates:
        if c_path.is_file():
            return str(c_path)
    raise PcapParserError(
        "O 'tshark' não foi encontrado. Instala o Wireshark/TShark, "
        "adiciona-o ao PATH ou define TSHARK_PATH."
    )


def _run_tshark_json(pcap_filepath: str, display_filter: str,
                     fields: list[str]) -> list[dict[str, Any]]:
    if not os.path.isfile(pcap_filepath):
        raise PcapParserError(f"Ficheiro PCAP não encontrado: {pcap_filepath}")
    command = [find_tshark_binary(), "-n", "-2", "-r", str(pcap_filepath),
               "-Y", display_filter, "-T", "json"]
    for field in fields:
        command.extend(["-e", field])
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", check=True,
                                timeout=120)
        packets = json.loads(result.stdout) if result.stdout.strip() else []
        if not isinstance(packets, list) or any(not isinstance(p, dict) for p in packets):
            raise PcapParserError("Resultado TShark inválido: era esperada uma lista de pacotes.")
        if result.stderr.strip():
            logger.warning("TShark: %s", result.stderr.strip())
        return packets
    except OSError as exc:
        raise PcapParserError(f"Não foi possível executar o tshark: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PcapParserError("A análise TShark excedeu o limite de 120 segundos.") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() if exc.stderr else str(exc)
        raise PcapParserError(f"Erro ao executar o tshark: {detail}") from exc
    except json.JSONDecodeError as exc:
        raise PcapParserError(f"Erro a interpretar o resultado do tshark: {exc}") from exc


def _get_field_first(layers: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for key in keys:
        values = _get_field_list(layers, key)
        if values:
            return values[0]
    return default


def _get_field_list(layers: dict[str, Any], key: str) -> list[str]:
    value = layers.get(key)
    values = value if isinstance(value, list) else [value]
    return [str(item) for item in values if item is not None and str(item) != ""]


def _number(value: Any) -> int | None:
    try:
        raw = str(value).strip().lower()
        return int(raw, 16 if raw.startswith("0x") else 10)
    except (ValueError, TypeError):
        return None


def _normalize_tls_version(version_raw: str | None) -> str | None:
    if not version_raw:
        return None
    num = _number(version_raw)
    if num is None:
        return version_raw
    return {768: "SSL 3.0", 769: "TLS 1.0", 770: "TLS 1.1",
            771: "TLS 1.2", 772: "TLS 1.3"}.get(num, version_raw)


_COMMON_FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst",
                  "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport"]


def _packet_metadata(layers: dict[str, Any]) -> dict[str, Any]:
    return {
        "packet_number": _number(_get_field_first(layers, ["frame.number"])),
        "stream_id": _get_field_first(layers, ["tcp.stream"]),
        "timestamp": _get_field_first(layers, ["frame.time_epoch"]),
        "source_ip": _get_field_first(layers, ["ip.src", "ipv6.src"]),
        "destination_ip": _get_field_first(layers, ["ip.dst", "ipv6.dst"]),
        "source_port": _get_field_first(layers, ["tcp.srcport"]),
        "destination_port": _get_field_first(layers, ["tcp.dstport"]),
    }


def extract_tls_metadata(pcap_filepath: str) -> list[dict[str, Any]]:
    """Extract Hello proposals and selections with packet/stream provenance.

    TLS 1.3's supported_versions overrides legacy_version (RFC 8446).
    """
    fields = _COMMON_FIELDS + [
        "tls.handshake.type", "tls.record.version", "tls.handshake.version",
        "tls.handshake.random", "tls.handshake.extensions.supported_version",
        "tls.handshake.ciphersuite", "tls.handshake.extensions_supported_group",
        "tls.handshake.extensions_key_share_group", "tls.handshake.extensions_server_name",
        "tls.handshake.sig_hash_alg",
    ]
    packets = _run_tshark_json(str(pcap_filepath), "tls.handshake.type in {1, 2}", fields)
    entries = []
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        types = [_number(raw) for raw in _get_field_list(layers, "tls.handshake.type")]
        hello_types = [handshake_type for handshake_type in types if handshake_type in {1, 2}]
        # Flattened fields cannot associate multiple Hellos, even of one type.
        if len(hello_types) != 1:
            logger.warning("Skipping ambiguous TLS Hello frame %s", layers.get("frame.number"))
            continue
        handshake_type = hello_types[0]
        versions_raw = _get_field_list(layers, "tls.handshake.extensions.supported_version")
        known_versions = [v for v in versions_raw if _number(v) in range(768, 773)]
        supported_versions = (
            [v for v in versions_raw
             if parse_identifier(v) is not None and not is_grease(parse_identifier(v))]
            if handshake_type == 1 else versions_raw
        )
        version_raw = (max(known_versions, key=lambda v: _number(v) or 0) if known_versions
                       else _get_field_first(layers, ["tls.handshake.version", "tls.record.version"]))
        if handshake_type == 2 and versions_raw:
            # The server selection overrides legacy fields even when unknown.
            version_raw = versions_raw[0]
        ciphers = _get_field_list(layers, "tls.handshake.ciphersuite")
        shares = _get_field_list(layers, "tls.handshake.extensions_key_share_group")
        random_value = str(_get_field_first(layers, ["tls.handshake.random"], "")).replace(":", "").lower()
        retry = random_value == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        entries.append({
            **_packet_metadata(layers),
            "handshake_type": "Client Hello" if handshake_type == 1 else "Server Hello",
            "tls_version": _normalize_tls_version(version_raw),
            "supported_versions": [_normalize_tls_version(v) for v in supported_versions],
            "cipher_suites": ciphers,
            "selected_cipher": ciphers[0] if handshake_type == 2 and len(ciphers) == 1 and not retry else None,
            "supported_groups": _get_field_list(layers, "tls.handshake.extensions_supported_group"),
            "key_share_groups": shares,
            "selected_group": shares[0] if handshake_type == 2 and len(shares) == 1 and not retry else None,
            "server_name": _get_field_first(layers, ["tls.handshake.extensions_server_name"]),
            "signature_algorithms": _get_field_list(layers, "tls.handshake.sig_hash_alg"),
            "hello_retry_request": retry,
        })
    return entries


def extract_ssh_metadata(pcap_filepath: str) -> list[dict[str, Any]]:
    field_map = {
        "kex_algorithms": "ssh.kex_algorithms",
        "server_host_key_algorithms": "ssh.server_host_key_algorithms",
        "encryption_client_to_server": "ssh.encryption_algorithms_client_to_server",
        "encryption_server_to_client": "ssh.encryption_algorithms_server_to_client",
        "mac_client_to_server": "ssh.mac_algorithms_client_to_server",
        "mac_server_to_client": "ssh.mac_algorithms_server_to_client",
    }
    packets = _run_tshark_json(str(pcap_filepath), "ssh.protocol or ssh.kex_algorithms",
                              _COMMON_FIELDS + ["ssh.protocol", *field_map.values()])
    entries = []
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        entry = _packet_metadata(layers)
        src, dst = _number(entry["source_port"]), _number(entry["destination_port"])
        entry["is_server"] = (src == 22) if (src == 22) != (dst == 22) else None
        entry["role_source"] = "standard-port" if entry["is_server"] is not None else None
        entry["protocol_banner"] = _get_field_first(layers, ["ssh.protocol"])
        for name, field in field_map.items():
            entry[name] = [part.strip() for value in _get_field_list(layers, field)
                           for part in value.split(",") if part.strip()]
        entries.append(entry)
    return entries


def detect_cleartext_traffic(pcap_filepath: str) -> list[dict[str, Any]]:
    """Report decoded plaintext messages, excluding TLS and upgrade preambles.

    PostgreSQL SSL requests/responses, SMTP EHLO/STARTTLS, FTP AUTH TLS/SSL
    and LDAP StartTLS requests do not prove unencrypted application use.
    """
    fields = _COMMON_FIELDS + [
        "http.request.method", "http.host", "http.response.code",
        "ftp.request.command", "ftp.request.arg", "ftp.response.code", "telnet",
        "ldap.protocolOp", "ldap.requestName",
        "pgsql.type", "smtp.req.command", "tcp.payload",
        "tls.record.version", "frame.protocols",
    ]
    packets = _run_tshark_json(
        str(pcap_filepath),
        "(http.request or http.response or ftp or telnet or ldap or pgsql or smtp.req.command) and not tls", fields,
    )
    entries = []
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        # Decoding application fields does not prove plaintext transport.
        protocols = {name for value in _get_field_list(layers, "frame.protocols")
                     for name in value.split(":")}
        if _get_field_list(layers, "tls.record.version") or "tls" in protocols:
            continue
        method = _get_field_first(layers, ["http.request.method"])
        http_status = _get_field_first(layers, ["http.response.code"])
        ftp_command = _get_field_first(layers, ["ftp.request.command"])
        pg_type = _get_field_first(layers, ["pgsql.type"])
        smtp_command = _get_field_first(layers, ["smtp.req.command"])
        protocol, snippet = None, None
        if method or http_status:
            protocol, snippet = "HTTP", f"HTTP {method or http_status}"
        elif ftp_command or layers.get("ftp.response.code"):
            if (ftp_command and ftp_command.upper() == "AUTH"
                    and _get_field_first(layers, ["ftp.request.arg"], "").strip().upper() in {"TLS", "SSL"}):
                continue
            protocol = "FTP"
            snippet = f"FTP {ftp_command or _get_field_first(layers, ['ftp.response.code'])}"
        elif layers.get("telnet"):
            protocol, snippet = "Telnet", "Decoded Telnet traffic"
        elif layers.get("ldap.protocolOp"):
            if (_number(_get_field_first(layers, ["ldap.protocolOp"])) == 23
                    and _get_field_first(layers, ["ldap.requestName"]) == "1.3.6.1.4.1.1466.20037"):
                continue
            protocol, snippet = "LDAP", "Decoded LDAP operation"
        elif pg_type and pg_type not in {"SSL request", "SSL response", "GSSENC request", "GSSENC response"}:
            protocol, snippet = "PostgreSQL", f"PostgreSQL {pg_type}"
        elif smtp_command and smtp_command.upper() in {"MAIL", "RCPT", "DATA", "AUTH"}:
            protocol, snippet = "SMTP", f"SMTP {smtp_command.upper()}"
        elif pg_type is None and "5432" in [str(_get_field_first(layers, ["tcp.srcport"])),
                                            str(_get_field_first(layers, ["tcp.dstport"]))]:
            try:
                payload = bytes.fromhex(str(_get_field_first(layers, ["tcp.payload"], "")).replace(":", ""))
            except ValueError:
                payload = b""
            if len(payload) >= 9 and payload[4:8] == b"\x00\x03\x00\x00" and int.from_bytes(payload[:4], "big") == len(payload):
                protocol, snippet = "PostgreSQL", "PostgreSQL protocol 3.0 StartupMessage"
        if protocol:
            entries.append({**_packet_metadata(layers), "protocol": protocol,
                            "http_method": method,
                            "http_host": _get_field_first(layers, ["http.host"]),
                            "matched_snippet": snippet})
    return entries


def parse_network_pcap(pcap_filepath: str) -> dict[str, Any]:
    """Return protocol metadata for consumers needing more than findings."""
    return {"pcap_file": str(pcap_filepath),
            "tls_sessions": extract_tls_metadata(pcap_filepath),
            "ssh_sessions": extract_ssh_metadata(pcap_filepath),
            "cleartext_traffic": detect_cleartext_traffic(pcap_filepath)}


def scan(path: Path) -> list[CryptoFinding]:
    """Return network assets conforming to scanner.models and Scanner.scan.

    Raw extractors remain available for packet-level inspection. Each finding
    carries validated evidence; risk fields retain the model's UNKNOWN defaults.
    """
    path = Path(path)
    return findings_from_metadata(parse_network_pcap(str(path)), path)


def parse_network_json(pcap_filepath: str | Path, *, indent: int | None = 2) -> str:
    """Serialize the validated findings using the shared model's JSON format."""
    return json.dumps([finding.to_dict() for finding in scan(Path(pcap_filepath))],
                      ensure_ascii=False, indent=indent)

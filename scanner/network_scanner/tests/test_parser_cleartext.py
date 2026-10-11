"""Cleartext extraction tests: protocol evidence, upgrades and privacy."""
from __future__ import annotations

import json
import struct
from unittest.mock import Mock

import pytest

from scanner.network_scanner.parser import tshark_parser as parser


def packet(fields: dict, *, source_port: str = "40000", destination_port: str = "5432") -> dict:
    return {"_source": {"layers": {
        "frame.number": ["73"], "frame.time_epoch": ["1790000000.125"],
        "tcp.stream": ["12"], "ip.src": ["192.0.2.10"], "ip.dst": ["192.0.2.20"],
        "tcp.srcport": [source_port], "tcp.dstport": [destination_port], **fields,
    }}}


def extract(monkeypatch, fields: dict, **ports) -> list[dict]:
    runner = Mock(return_value=[packet(fields, **ports)])
    monkeypatch.setattr(parser, "_run_tshark_json", runner)
    return parser.detect_cleartext_traffic("capture.pcap")


@pytest.mark.parametrize(("fields", "protocol", "snippet"), [
    ({"http.request.method": ["POST"], "http.host": ["api.example.test"]}, "HTTP", "HTTP POST"),
    ({"http.response.code": ["200"]}, "HTTP", "HTTP 200"),
    ({"ftp.request.command": ["PASS"]}, "FTP", "FTP PASS"),
    ({"ftp.response.code": ["230"]}, "FTP", "FTP 230"),
    ({"ldap.protocolOp": ["0"]}, "LDAP", "Decoded LDAP operation"),
    ({"telnet": ["Telnet"]}, "Telnet", "Decoded Telnet traffic"),
    ({"pgsql.type": ["Simple query"]}, "PostgreSQL", "PostgreSQL Simple query"),
    ({"pgsql.type": ["Authentication request"]}, "PostgreSQL", "PostgreSQL Authentication request"),
    ({"smtp.req.command": ["MAIL"]}, "SMTP", "SMTP MAIL"),
    ({"smtp.req.command": ["RCPT"]}, "SMTP", "SMTP RCPT"),
    ({"smtp.req.command": ["DATA"]}, "SMTP", "SMTP DATA"),
    ({"smtp.req.command": ["auth"]}, "SMTP", "SMTP AUTH"),
], ids=["http-request", "http-response", "ftp-request", "ftp-response", "ldap-bind", "telnet",
        "postgres-query", "postgres-authentication", "smtp-mail", "smtp-rcpt", "smtp-data", "smtp-auth"])
def test_decoded_application_messages_have_packet_and_endpoint_provenance(monkeypatch, fields, protocol, snippet):
    # Use an unusual destination port: decoding, rather than a port number,
    # establishes that these are plaintext application messages.
    """Verifica protocolos descodificados e preserva pacote, ligacao, timestamp e endpoints, mesmo em portas nao habituais."""
    result = extract(monkeypatch, fields, destination_port="41000")
    assert len(result) == 1
    entry = result[0]
    assert entry["protocol"] == protocol
    assert entry["matched_snippet"] == snippet
    assert entry["packet_number"] == 73
    assert entry["stream_id"] == "12"
    assert entry["timestamp"] == "1790000000.125"
    assert (entry["source_ip"], entry["destination_ip"]) == ("192.0.2.10", "192.0.2.20")
    assert (entry["source_port"], entry["destination_port"]) == ("40000", "41000")


@pytest.mark.parametrize("port", ["21", "23", "25", "80", "389", "443", "465", "5432"])
def test_well_known_ports_without_decoded_application_data_are_not_cleartext(monkeypatch, port):
    """Impede classificar trafego como cleartext apenas por utilizar uma porta conhecida."""
    assert extract(monkeypatch, {}, destination_port=port) == []
    assert extract(monkeypatch, {}, source_port=port, destination_port="40000") == []


def test_http_host_alone_is_not_a_request_or_response(monkeypatch):
    """Verifica que o host HTTP isolado nao constitui evidencia de um pedido ou resposta."""
    assert extract(monkeypatch, {"http.host": ["example.test"]}, destination_port="80") == []


@pytest.mark.parametrize("message", ["SSL request", "SSL response", "GSSENC request", "GSSENC response"])
def test_decoded_postgres_tls_and_gss_upgrade_preambles_are_excluded(monkeypatch, message):
    """Exclui mensagens PostgreSQL de atualizacao para TLS ou GSS da detecao de aplicacao em claro."""
    assert extract(monkeypatch, {"pgsql.type": [message]}) == []


@pytest.mark.parametrize("command", ["EHLO", "ehlo", "HELO", "STARTTLS", "starttls", "QUIT", "NOOP"])
def test_smtp_upgrade_and_greeting_commands_do_not_prove_cleartext_application_use(monkeypatch, command):
    """Exclui saudacoes, pedidos STARTTLS e comandos SMTP que nao provam utilizacao de aplicacao em claro."""
    assert extract(monkeypatch, {"smtp.req.command": [command]}, destination_port="25") == []


@pytest.mark.parametrize(("command", "argument"), [
    ("AUTH", "TLS"), ("AUTH", "SSL"), ("auth", "tls"), ("auth", " ssl "),
])
def test_ftp_tls_upgrade_requests_do_not_prove_cleartext_application_use(monkeypatch, command, argument):
    assert extract(monkeypatch, {
        "ftp.request.command": [command], "ftp.request.arg": [argument],
    }, destination_port="21") == []
    assert "ftp.request.arg" in parser._run_tshark_json.call_args.args[2]


@pytest.mark.parametrize("fields", [
    {"ftp.request.command": ["AUTH"], "ftp.request.arg": ["GSSAPI"]},
    {"ftp.request.command": ["AUTH"]},
    {"ftp.request.command": ["PASS"], "ftp.request.arg": ["TLS"]},
])
def test_ftp_other_authentication_and_credentials_remain_plaintext(monkeypatch, fields):
    [entry] = extract(monkeypatch, fields, destination_port="21")
    assert entry["protocol"] == "FTP"


@pytest.mark.parametrize("operation", ["23", "0x17"])
def test_ldap_starttls_requests_do_not_prove_cleartext_application_use(monkeypatch, operation):
    assert extract(monkeypatch, {
        "ldap.protocolOp": [operation], "ldap.requestName": ["1.3.6.1.4.1.1466.20037"],
    }, destination_port="389") == []
    assert "ldap.requestName" in parser._run_tshark_json.call_args.args[2]


@pytest.mark.parametrize("fields", [
    {"ldap.protocolOp": ["23"], "ldap.requestName": ["1.3.6.1.4.1.4203.1.11.1"]},
    {"ldap.protocolOp": ["23"]},
    {"ldap.protocolOp": ["0"], "ldap.requestName": ["1.3.6.1.4.1.1466.20037"]},
])
def test_ldap_other_operations_remain_plaintext(monkeypatch, fields):
    [entry] = extract(monkeypatch, fields, destination_port="389")
    assert entry["protocol"] == "LDAP"


def startup(*, version: int = 196608, body: bytes = b"user\x00private-user\x00database\x00private-db\x00\x00") -> bytes:
    return struct.pack("!II", 8 + len(body), version) + body


@pytest.mark.parametrize("colon_hex", [False, True], ids=["compact-hex", "tshark-colon-hex"])
@pytest.mark.parametrize("direction", ["client", "server"])
def test_postgres_v3_startup_header_is_detected_without_copying_parameters(monkeypatch, colon_hex, direction):
    """Reconhece o cabecalho StartupMessage PostgreSQL 3.0 em ambas as direcoes sem exportar parametros ou payload."""
    raw = startup()
    payload = raw.hex(":") if colon_hex else raw.hex()
    ports = {"source_port": "5432", "destination_port": "40000"} if direction == "server" else {}
    result = extract(monkeypatch, {"tcp.payload": [payload]}, **ports)
    assert len(result) == 1
    assert result[0]["protocol"] == "PostgreSQL"
    assert result[0]["matched_snippet"] == "PostgreSQL protocol 3.0 StartupMessage"
    serialized = json.dumps(result)
    assert "private-user" not in serialized and "private-db" not in serialized
    assert payload not in serialized
    assert "tcp.payload" not in serialized


_VALID_STARTUP = startup()
@pytest.mark.parametrize("payload", [
    "", "not-hex", "0", "00:00:zz:01",
    _VALID_STARTUP[:3].hex(), _VALID_STARTUP[:7].hex(), _VALID_STARTUP[:-1].hex(),
    (struct.pack("!I", len(_VALID_STARTUP) + 1) + _VALID_STARTUP[4:]).hex(),
    (struct.pack("!I", len(_VALID_STARTUP) - 1) + _VALID_STARTUP[4:]).hex(),
    startup(version=262144).hex(), startup(version=196609).hex(),
    struct.pack("!II", 8, 80877103).hex(),  # SSLRequest
    struct.pack("!II", 8, 80877104).hex(),  # GSSENCRequest
    b"S".hex(), b"N".hex(), b"G".hex(),
], ids=["empty", "invalid-hex", "odd-hex", "invalid-colon-hex", "truncated-length", "truncated-version",
        "truncated-body", "declared-length-too-long", "declared-length-too-short", "wrong-major-version",
        "wrong-minor-version", "ssl-request", "gss-request", "ssl-accepted", "ssl-refused", "gss-accepted"])
def test_invalid_or_upgrade_payloads_do_not_create_postgres_cleartext_findings(monkeypatch, payload):
    """Rejeita payloads invalidos, truncados, com comprimentos inconsistentes ou pertencentes a negociacao TLS/GSS."""
    assert extract(monkeypatch, {"tcp.payload": [payload]}) == []


def test_valid_postgres_header_on_unrelated_port_is_not_assumed_postgres(monkeypatch):
    """Impede identificar PostgreSQL apenas pelo cabecalho bruto quando a porta nao corresponde ao protocolo esperado."""
    assert extract(monkeypatch, {"tcp.payload": [startup().hex()]}, destination_port="41000") == []


@pytest.mark.parametrize("fields", [
    {"http.request.method": ["GET"], "http.request.uri": ["/login?token=DO_NOT_EXPORT"]},
    {"ftp.request.command": ["PASS"], "ftp.request.arg": ["DO_NOT_EXPORT"]},
    {"ldap.protocolOp": ["0"], "ldap.simple": ["DO_NOT_EXPORT"]},
    {"telnet": ["Telnet"], "telnet.data": ["DO_NOT_EXPORT"]},
    {"pgsql.type": ["Password message"], "pgsql.password": ["DO_NOT_EXPORT"]},
    {"smtp.req.command": ["AUTH"], "smtp.req.parameter": ["DO_NOT_EXPORT"]},
])
def test_protocol_evidence_does_not_export_sensitive_payload_or_protocol_parameters(monkeypatch, fields):
    """Verifica que a evidencia identifica o protocolo sem exportar passwords, tokens ou outros parametros sensiveis."""
    fields = {**fields, "tcp.payload": [b"DO_NOT_EXPORT".hex()]}
    result = extract(monkeypatch, fields)
    assert len(result) == 1
    serialized = json.dumps(result)
    assert "DO_NOT_EXPORT" not in serialized
    assert b"DO_NOT_EXPORT".hex() not in serialized
    assert "tcp.payload" not in serialized


def test_ipv6_application_packet_has_addresses_without_invented_ipv4_defaults(monkeypatch):
    """Preserva os enderecos IPv6 de trafego de aplicacao sem inventar enderecos IPv4."""
    decoded = packet({"http.response.code": ["204"]})
    layers = decoded["_source"]["layers"]
    del layers["ip.src"], layers["ip.dst"]
    layers.update({"ipv6.src": ["2001:db8::1"], "ipv6.dst": ["2001:db8::2"]})
    monkeypatch.setattr(parser, "_run_tshark_json", Mock(return_value=[decoded]))
    entry = parser.detect_cleartext_traffic("capture.pcap")[0]
    assert (entry["source_ip"], entry["destination_ip"]) == ("2001:db8::1", "2001:db8::2")


def test_empty_tshark_result_has_no_cleartext_findings(monkeypatch):
    """Verifica que a ausencia de pacotes do TShark produz uma lista vazia de resultados cleartext."""
    monkeypatch.setattr(parser, "_run_tshark_json", Mock(return_value=[]))
    assert parser.detect_cleartext_traffic("capture.pcap") == []


@pytest.mark.parametrize("tls_fields", [
    {"tls.record.version": ["0x0303"]},
    {"frame.protocols": ["eth:ip:tcp:tls:http"]},
    {"tls.record.version": ["0x0303"], "frame.protocols": ["eth:ip:tcp:tls:http"]},
], ids=["record-version", "protocol-stack", "both"])
@pytest.mark.parametrize("http_fields", [
    {"http.request.method": ["GET"]}, {"http.response.code": ["200"]},
], ids=["tls-http-request", "tls-http-response"])
def test_decoded_http_inside_tls_is_not_reported_as_cleartext(monkeypatch, http_fields, tls_fields):
    """Exclui pedidos e respostas HTTP dentro de TLS usando cada evidencia de transporte disponivel."""
    # TShark can decode encrypted application messages using a configured
    # key log or PCAPNG Decryption Secrets Block. Decoding is not evidence
    # that the original transport was plaintext.
    fields = {**http_fields, **tls_fields}
    assert extract(monkeypatch, fields, destination_port="443") == []

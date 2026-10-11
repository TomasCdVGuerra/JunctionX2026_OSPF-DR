"""Finding/JSON contracts at the public parser API, without model mocks.

The only mocked boundary is parse_network_pcap. Inputs are independent metadata
observations; returned models and their JSON pass through real validation.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scanner.models import AssetType, CryptoFinding, CryptoFunction, QuantumRiskLevel
from scanner.network_scanner.parser import tshark_parser as parser


@pytest.fixture
def parsed_metadata(monkeypatch):
    parse = Mock()
    monkeypatch.setattr(parser, "parse_network_pcap", parse)

    def set_metadata(*, tls=(), ssh=(), cleartext=()):
        metadata = {"pcap_file": "raw-input.pcap", "tls_sessions": list(tls),
                    "ssh_sessions": list(ssh), "cleartext_traffic": list(cleartext)}
        parse.return_value = copy.deepcopy(metadata)
        return parse

    return set_metadata


def _tls(**changes):
    return {"packet_number": 42, "stream_id": "7", "timestamp": "1780000000.125",
            "source_ip": "192.0.2.10", "destination_ip": "198.51.100.20",
            "source_port": "49152", "destination_port": "443", "server_name": "service.example",
            "handshake_type": "Client Hello", "tls_version": "TLS 1.3",
            "supported_versions": ["TLS 1.3"], "cipher_suites": [], "selected_cipher": None,
            "supported_groups": [], "key_share_groups": [], "selected_group": None,
            "signature_algorithms": [], "hello_retry_request": False, **changes}


def _ssh(**changes):
    return {"packet_number": 53, "stream_id": "8", "timestamp": "1780000001.5",
            "source_ip": "2001:db8::10", "destination_ip": "2001:db8::20",
            "source_port": "49153", "destination_port": "22", "is_server": False,
            "role_source": "standard-port", "protocol_banner": None, "kex_algorithms": [],
            "server_host_key_algorithms": [], "encryption_client_to_server": [],
            "encryption_server_to_client": [], "mac_client_to_server": [],
            "mac_server_to_client": [], **changes}


def _algorithms(findings):
    return [finding for finding in findings if finding.asset_type == AssetType.ALGORITHM]


def _assert_no_assessment(findings):
    for finding in findings:
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN
        assert finding.recommendation is None
        assert all(evidence.risk_reasoning is None for evidence in finding.evidence)


def test_scan_returns_valid_shared_models_and_preserves_input_provenance(parsed_metadata, tmp_path):
    """Verifica que scan devolve models validos com caminho, pacote e evidencia de origem, sem avaliar riscos."""
    parse = parsed_metadata(tls=[_tls(cipher_suites=["0x1301"])])
    path = tmp_path / "captura-revisão.pcap"
    findings = parser.scan(path)
    assert findings and all(isinstance(finding, CryptoFinding) for finding in findings)
    assert parse.call_count == 1
    assert Path(parse.call_args.args[0]) == path
    for finding in findings:
        assert finding.source_type == "network-capture"
        assert finding.observation == "advertised"
        assert finding.evidence
        assert all(evidence.file_path == str(path) and evidence.packet_number == 42
                   and evidence.rule_id for evidence in finding.evidence)
        assert CryptoFinding.model_validate(finding.to_dict()) == finding
    _assert_no_assessment(findings)


@pytest.mark.parametrize("cipher,cipher_name,key_size,mode,hash_name", [
    ("0x1301", "AES", 128, "GCM", "SHA-256"),
    ("0x1302", "AES", 256, "GCM", "SHA-384"),
    ("0x1303", "ChaCha20-Poly1305", 256, None, "SHA-256"),
])
def test_tls13_suite_yields_cipher_digest_and_kdf_without_inventing_public_key_algorithms(
        parsed_metadata, tmp_path, cipher, cipher_name, key_size, mode, hash_name):
    """Decompoe suites TLS 1.3 em cifra, digest e KDF, sem inferir troca de chaves ou assinatura pela suite."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", selected_cipher=cipher,
                             cipher_suites=[cipher], server_name=None)])
    findings = parser.scan(tmp_path / "tls13.pcap")
    algorithms = _algorithms(findings)
    assert {(f.algorithm_name, f.crypto_function) for f in algorithms} == {
        (cipher_name, CryptoFunction.ENCRYPT), (hash_name, CryptoFunction.DIGEST),
        (f"HKDF-{hash_name}", CryptoFunction.KDF),
    }
    [encryption] = [f for f in algorithms if f.crypto_function == CryptoFunction.ENCRYPT]
    assert (encryption.key_size, encryption.mode) == (key_size, mode)
    assert all(f.observation == "negotiated" for f in algorithms)
    assert all(f.protocol == "TLS 1.3" for f in algorithms)
    assert not any(f.crypto_function in {CryptoFunction.KEY_EXCHANGE, CryptoFunction.SIGN} for f in algorithms)
    _assert_no_assessment(findings)


def test_tls12_suite_emits_individual_primitives_and_keeps_rsa_size_unknown(parsed_metadata, tmp_path):
    """Decompoe uma suite TLS 1.2 sem inventar o tamanho RSA nem tratar o hash do MAC como digest independente."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", tls_version="TLS 1.2",
                             supported_versions=[], cipher_suites=["0x002f"], selected_cipher="0x002f")])
    findings = parser.scan(tmp_path / "tls12.pcap")
    algorithms = _algorithms(findings)
    assert {(f.algorithm_name, f.crypto_function) for f in algorithms} == {
        ("RSA", CryptoFunction.KEY_EXCHANGE), ("AES", CryptoFunction.ENCRYPT),
        ("HMAC-SHA-1", CryptoFunction.MAC),
        ("TLS-PRF-SHA-256", CryptoFunction.KDF),
    }
    [rsa] = [f for f in algorithms if f.algorithm_name == "RSA"]
    assert rsa.key_size is None
    assert rsa.padding is None
    assert not any(f.algorithm_name == "SHA-1" and f.crypto_function == CryptoFunction.DIGEST
                   for f in algorithms)
    [aes] = [f for f in algorithms if f.algorithm_name == "AES"]
    assert (aes.key_size, aes.mode) == (128, "CBC")
    _assert_no_assessment(findings)


def test_tls_client_groups_signatures_and_cipher_options_are_advertised(parsed_metadata, tmp_path):
    """Marca cifras, grupos e assinaturas do ClientHello como anunciados, preservando os parametros conhecidos."""
    parsed_metadata(tls=[_tls(cipher_suites=["0x1301", "0x1302"],
                             supported_groups=["29", "4588"], key_share_groups=["29"],
                             signature_algorithms=["0x0804"])])
    findings = parser.scan(tmp_path / "offers.pcap")
    algorithms = _algorithms(findings)
    assert all(f.observation == "advertised" for f in algorithms)
    assert {(f.key_size, f.mode) for f in algorithms if f.algorithm_name == "AES"} == {(128, "GCM"), (256, "GCM")}
    assert {"ECDHE-X25519", "X25519MLKEM768"}.issubset({f.algorithm_name for f in algorithms})
    assert any(f.algorithm_name == "RSA" and f.crypto_function == CryptoFunction.SIGN
               and f.padding == "PSS" and f.key_size is None for f in algorithms)
    assert not any(f.observation == "negotiated" for f in findings)
    _assert_no_assessment(findings)


@pytest.mark.parametrize("cipher,version", [("0x1302", "TLS 1.2"), ("0xc02f", "TLS 1.3")])
def test_incompatible_server_selection_preserves_evidence_without_valid_primitives(parsed_metadata, tmp_path, cipher, version):
    """Sinaliza selecao inconsistente preservando codigo, versao, pacote e riscos desconhecidos."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", tls_version=version,
                             selected_cipher=cipher, cipher_suites=[cipher])])
    findings = parser.scan(tmp_path / "incompatible.pcap")
    [finding] = _algorithms(findings)
    assert finding.algorithm_name == f"TLS-CIPHER-{cipher}"
    assert finding.crypto_function == CryptoFunction.UNKNOWN
    assert finding.observation == "negotiated" and finding.protocol == version
    details = json.loads(finding.evidence[0].matched_snippet)
    assert details["mapping_status"] == "incompatible-version"
    assert details["cipher_suite"] == cipher and details["cipher_suite_name"]
    assert finding.evidence[0].packet_number == 42
    _assert_no_assessment(findings)


@pytest.mark.parametrize("version", ["TLS 1.2", "TLS 1.3"])
def test_mixed_client_cipher_proposals_are_not_incompatible_selections(parsed_metadata, tmp_path, version):
    """Aceita propostas de suites TLS 1.2 e 1.3 no mesmo ClientHello sem inventar selecao."""
    parsed_metadata(tls=[_tls(tls_version=version, supported_versions=["TLS 1.3", "TLS 1.2"],
                             cipher_suites=["0x1302", "0xc02f"])])
    findings = parser.scan(tmp_path / "mixed-proposals.pcap")
    algorithms = _algorithms(findings)
    assert any(f.algorithm_name == "AES" and f.key_size == 256 for f in algorithms)
    assert any(f.algorithm_name == "AES" and f.key_size == 128 for f in algorithms)
    assert any(f.algorithm_name == "ECDHE" for f in algorithms)
    assert all(f.observation == "advertised" for f in algorithms)
    assert all("mapping_status" not in json.loads(e.matched_snippet)
               for f in findings for e in f.evidence)


def test_tls_server_uses_only_explicit_selected_cipher_and_group(parsed_metadata, tmp_path):
    """Usa apenas cifra e grupo explicitamente selecionados no ServerHello, sem promover propostas ou assinaturas."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", cipher_suites=["0x1301", "0x1302"],
                             selected_cipher="0x1302", supported_groups=["29"], key_share_groups=["29"],
                             selected_group="4588", signature_algorithms=["0x0804"])])
    algorithms = _algorithms(parser.scan(tmp_path / "selected.pcap"))
    assert any(f.algorithm_name == "AES" and f.key_size == 256 for f in algorithms)
    assert any(f.algorithm_name == "X25519MLKEM768" and f.crypto_function == CryptoFunction.KEY_EXCHANGE
               and f.key_size is None for f in algorithms)
    assert not any(f.algorithm_name == "AES" and f.key_size == 128 for f in algorithms)
    assert not any(f.algorithm_name in {"ECDHE-X25519", "RSA"} for f in algorithms)
    assert not any(f.crypto_function == CryptoFunction.SIGN for f in algorithms)
    assert all(f.observation == "negotiated" for f in algorithms)


def test_tls_server_does_not_promote_offer_lists_when_selection_is_missing(parsed_metadata, tmp_path):
    """Impede transformar listas de propostas do ServerHello em algoritmos negociados quando falta a selecao."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", cipher_suites=["0x1301"],
                             supported_groups=["29"], key_share_groups=["29"], signature_algorithms=["0x0804"])])
    assert _algorithms(parser.scan(tmp_path / "missing-selection.pcap")) == []


def test_hello_retry_request_produces_no_negotiated_algorithm_even_if_selection_fields_present(parsed_metadata, tmp_path):
    """Impede produzir algoritmos negociados a partir de HelloRetryRequest, mesmo com campos de selecao presentes."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", hello_retry_request=True,
                             selected_cipher="0x1302", selected_group="4588", cipher_suites=["0x1302"])])
    algorithms = _algorithms(parser.scan(tmp_path / "retry.pcap"))
    assert not any(f.observation == "negotiated" for f in algorithms)


@pytest.mark.parametrize("handshake,observation", [("Client Hello", "advertised"), ("Server Hello", "negotiated")])
def test_unknown_tls_ids_are_explicit_and_keep_unknown_sizes_and_risks(parsed_metadata, tmp_path, handshake, observation):
    """Preserva identificadores TLS desconhecidos com o estado correto e sem inventar tamanhos ou riscos."""
    parsed_metadata(tls=[_tls(handshake_type=handshake, cipher_suites=["0xfefe"], selected_cipher="0xfefe",
                             supported_groups=["0xfdfd"], selected_group="0xfdfd",
                             signature_algorithms=["0xfcfc"])])
    findings = parser.scan(tmp_path / "unknown.pcap")
    algorithms = _algorithms(findings)
    names = {f.algorithm_name for f in algorithms}
    assert {"TLS-CIPHER-0xfefe", "TLS-GROUP-0xfdfd"}.issubset(names)
    assert ("TLS-SIGNATURE-0xfcfc" in names) == (handshake == "Client Hello")
    assert all(f.key_size is None and f.observation == observation for f in algorithms)
    _assert_no_assessment(findings)


def test_tls_reserved_grease_and_scsv_are_not_algorithms(parsed_metadata, tmp_path):
    """Exclui GREASE e SCSV dos resultados de algoritmos criptograficos."""
    parsed_metadata(tls=[_tls(cipher_suites=["0x0a0a", "0x00ff", "0x5600"],
                             supported_groups=["0x1a1a"], key_share_groups=["0x2a2a"],
                             signature_algorithms=["0x3a3a"])])
    assert _algorithms(parser.scan(tmp_path / "reserved.pcap")) == []


@pytest.mark.parametrize("field", ["kex_algorithms", "server_host_key_algorithms", "encryption_client_to_server",
                                   "encryption_server_to_client", "mac_client_to_server", "mac_server_to_client"])
@pytest.mark.parametrize("is_server", [False, True, None])
def test_unknown_ssh_proposals_in_every_direction_are_advertised_without_guessing_usage(
        parsed_metadata, tmp_path, field, is_server):
    """Preserva propostas SSH desconhecidas como anunciadas em todas as categorias, direcoes e papeis."""
    raw_algorithm = "custom-future-primitive@example.test"
    parsed_metadata(ssh=[_ssh(**{field: [raw_algorithm], "is_server": is_server})])
    findings = parser.scan(tmp_path / "ssh-offer.pcap")
    [finding] = [f for f in _algorithms(findings) if f.algorithm_name == raw_algorithm]
    assert finding.observation == "advertised"
    assert finding.protocol == "SSH"
    assert finding.key_size is None
    assert not any(f.observation == "negotiated" for f in findings)
    _assert_no_assessment(findings)


@pytest.mark.parametrize("field,raw_algorithm,name,function,key_size,mode", [
    ("kex_algorithms", "curve25519-sha256", "ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255, None),
    ("server_host_key_algorithms", "rsa-sha2-256", "RSA", CryptoFunction.SIGN, None, None),
    ("encryption_client_to_server", "aes256-gcm@openssh.com", "AES", CryptoFunction.ENCRYPT, 256, "GCM"),
    ("mac_server_to_client", "hmac-sha2-256", "HMAC-SHA-256", CryptoFunction.MAC, None, None),
])
def test_known_ssh_names_map_to_primitives_without_risk_or_negotiation(
        parsed_metadata, tmp_path, field, raw_algorithm, name, function, key_size, mode):
    """Traduz nomes SSH conhecidos em primitivas com parametros corretos, sem avaliar risco ou afirmar negociacao."""
    parsed_metadata(ssh=[_ssh(**{field: [raw_algorithm]})])
    findings = parser.scan(tmp_path / "known-ssh.pcap")
    matches = [f for f in _algorithms(findings) if f.algorithm_name == name and f.crypto_function == function]
    assert matches
    assert all((f.key_size, f.mode, f.observation) == (key_size, mode, "advertised") for f in matches)
    _assert_no_assessment(findings)


def test_ssh_banner_is_observed_protocol_not_an_algorithm(parsed_metadata, tmp_path):
    """Representa o banner SSH como protocolo observado, sem criar um algoritmo."""
    parsed_metadata(ssh=[_ssh(protocol_banner="SSH-2.0-Independent_Server", is_server=True)])
    findings = parser.scan(tmp_path / "banner.pcap")
    assert findings and _algorithms(findings) == []
    assert all(f.asset_type == AssetType.PROTOCOL and f.protocol == "SSH 2.0" and f.observation == "observed"
               for f in findings)
    _assert_no_assessment(findings)


def test_cleartext_is_observed_protocol_with_no_unrequested_risk_assessment(parsed_metadata, tmp_path):
    """Representa trafego em claro como protocolo observado, preservando o pacote e deixando a analise de risco pendente."""
    parsed_metadata(cleartext=[{"packet_number": 64, "stream_id": "9", "source_ip": "192.0.2.10",
                               "destination_ip": "198.51.100.20", "source_port": "49154",
                               "destination_port": "80", "protocol": "HTTP", "http_method": "GET",
                               "http_host": "intranet.example", "matched_snippet": "HTTP GET"}])
    [finding] = parser.scan(tmp_path / "cleartext.pcap")
    assert finding.asset_type == AssetType.PROTOCOL
    assert finding.algorithm_name == "Cleartext"
    assert finding.protocol == "HTTP"
    assert finding.observation == "observed"
    assert finding.key_size is None
    assert finding.evidence[0].packet_number == 64
    _assert_no_assessment([finding])


def test_evidence_uses_json_context_whitelist_instead_of_dumping_raw_metadata(parsed_metadata, tmp_path):
    """Inclui apenas campos de contexto permitidos na evidencia JSON e exclui conteudo bruto ou sensivel."""
    sentinel = "SHOULD_NEVER_APPEAR_IN_FINDING_JSON"
    entry = _tls(cipher_suites=["0x1301"], supported_groups=["29"], signature_algorithms=["0x0804"],
                 **{"tcp.payload": sentinel, "private_key": sentinel, "certificate_pem": sentinel,
                    "http_uri": sentinel, "http_body": sentinel, "untrusted_extra": {"password": sentinel}})
    parsed_metadata(tls=[entry])
    path = tmp_path / "whitelist.pcap"
    findings = parser.scan(path)
    assert findings
    context_keys = set()
    for finding in findings:
        for evidence in finding.evidence:
            context = json.loads(evidence.matched_snippet)
            assert isinstance(context, dict)
            assert context["stream_id"] == "7"
            assert context["source_ip"] == "192.0.2.10"
            assert context["destination_ip"] == "198.51.100.20"
            assert context["server_name"] == "service.example"
            assert not {"tcp.payload", "private_key", "certificate_pem", "http_uri", "http_body", "untrusted_extra"}.intersection(context)
            context_keys.update(context)
            assert evidence.file_path == str(path) and evidence.packet_number == 42 and evidence.rule_id
    assert {"cipher_suite", "group", "signature_scheme"}.issubset(context_keys)
    assert sentinel not in json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize("indent", [None, 2])
def test_public_json_array_serializes_enum_values_excludes_none_and_roundtrips_models(parsed_metadata, tmp_path, indent):
    """Verifica serializacao dos enums, exclusao de None, formatacao JSON e reconstrucao dos models."""
    parsed_metadata(tls=[_tls(handshake_type="Server Hello", selected_cipher="0x002f", cipher_suites=["0x002f"],
                             tls_version="TLS 1.2", supported_versions=[], source_ip=None, server_name=None)])
    path = tmp_path / "models-json.pcap"
    expected = parser.scan(path)
    result = parser.parse_network_json(path, indent=indent)
    assert isinstance(result, str)
    payload = json.loads(result)
    assert isinstance(payload, list) and payload
    assert payload == [finding.to_dict() for finding in expected]
    assert [CryptoFinding.model_validate(item) for item in payload] == expected
    for item in payload:
        assert item["source_type"] == "network-capture"
        assert item["asset_type"] in {"algorithm", "protocol"}
        assert item["quantum_risk"] == item["classical_risk"] == "unknown"
        assert isinstance(item["crypto_function"], str)
        assert set(item).issubset(CryptoFinding.model_fields)
        assert "recommendation" not in item and "oid" not in item
        assert all(value is not None for value in item.values())
        for evidence in item["evidence"]:
            assert "line_number" not in evidence and "risk_reasoning" not in evidence
            assert all(value is not None for value in evidence.values())
    rsa = next(item for item in payload if item["algorithm_name"] == "RSA")
    assert "key_size" not in rsa
    if indent is None:
        assert "\n" not in result
    else:
        assert result.startswith("[\n  {")


def test_adapter_excludes_host_credentials_and_raw_secrets(parsed_metadata, tmp_path):
    """Remove credenciais do host e preserva protocolo, endpoints e pacote na evidencia."""
    entry = {"protocol": "HTTP", "http_host": "user:SECRET@example.test:8080",
             "packet_number": 7, "source_ip": "192.0.2.1", "destination_ip": "192.0.2.2",
             "password": "SECRET", "payload": "SECRET", "matched_snippet": "SECRET"}
    before = copy.deepcopy(entry)
    parsed_metadata(cleartext=[entry])
    [finding] = parser.scan(tmp_path / "host.pcap")
    details = json.loads(finding.evidence[0].matched_snippet)
    assert details["http_host"] == "example.test:8080"
    assert details["source_ip"] == "192.0.2.1"
    assert details["destination_ip"] == "192.0.2.2"
    assert finding.evidence[0].packet_number == 7
    assert "SECRET" not in json.dumps(finding.to_dict())
    assert entry == before


def test_scan_and_json_of_empty_observations_return_empty_lists(parsed_metadata, tmp_path):
    """Verifica que ausencia de observacoes produz listas vazias em scan e na saida JSON."""
    parsed_metadata()
    path = tmp_path / "empty.pcap"
    assert parser.scan(path) == []
    assert json.loads(parser.parse_network_json(str(path))) == []


def test_conversion_does_not_mutate_raw_metadata_lists(parsed_metadata, tmp_path):
    """Verifica que a conversao para models nao modifica as listas nem os metadados de entrada."""
    parse = parsed_metadata(tls=[_tls(cipher_suites=["0x1301", "0x1302"], supported_groups=["29"])],
                            ssh=[_ssh(kex_algorithms=["curve25519-sha256"])])
    before = copy.deepcopy(parse.return_value)
    findings = parser.scan(tmp_path / "immutable.pcap")
    assert findings
    assert parse.return_value == before


@pytest.mark.parametrize("packet,expected", [(None, None), (True, None), (False, None),
                                            ("invalid", None), (0, None), (-2, None), ("73", 73),
                                            (1.9, None), (1.0, None), ("1.9", None),
                                            ("1_000", None), (73, 73), (" 73 ", 73)])
def test_evidence_never_invents_a_positive_packet_number(parsed_metadata, tmp_path, packet, expected):
    """Valida numeros de pacote e preserva a ausencia de um numero valido sem inventar evidencia."""
    parsed_metadata(tls=[_tls(packet_number=packet, cipher_suites=["0x1301"])])
    findings = parser.scan(tmp_path / "packet-number.pcap")
    assert findings
    assert all(e.packet_number == expected for finding in findings for e in finding.evidence)
    for finding in findings:
        for evidence in finding.evidence:
            context = json.loads(evidence.matched_snippet)
            if expected is None:
                assert "packet_number" not in context
            else:
                assert context["packet_number"] == expected
    assert all(CryptoFinding.model_validate(finding.to_dict()) == finding for finding in findings)


def test_ssh_negotiation_markers_are_not_reported_as_algorithms(parsed_metadata, tmp_path):
    """Exclui marcadores de negociacao SSH e elimina propostas duplicadas do mesmo algoritmo."""
    parsed_metadata(ssh=[_ssh(kex_algorithms=[
        "ext-info-c,ext-info-s,kex-strict-c-v00@openssh.com,kex-strict-s-v00@openssh.com",
        "curve25519-sha256, curve25519-sha256",
    ])])
    [finding] = parser.scan(tmp_path / "ssh-markers.pcap")
    assert finding.algorithm_name == "ECDHE-X25519"
    assert finding.observation == "advertised"


def test_cleartext_requires_a_protocol_not_only_a_port_or_payload(parsed_metadata, tmp_path):
    """Exige identificacao do protocolo para criar resultados cleartext, em vez de usar so porta ou payload."""
    parsed_metadata(cleartext=[{"destination_port": "80", "payload": "GET /"}, {"protocol": ""}])
    assert parser.scan(tmp_path / "unconfirmed-cleartext.pcap") == []


def test_non_hello_tls_metadata_does_not_create_algorithm_findings(parsed_metadata, tmp_path):
    """Ignora metadados TLS que nao correspondem a ClientHello ou ServerHello."""
    parsed_metadata(tls=[_tls(handshake_type="Certificate", cipher_suites=["0x1302"])])
    assert parser.scan(tmp_path / "not-a-hello.pcap") == []


def test_groups_are_deduplicated_by_numeric_id_without_losing_unknown_identifiers(parsed_metadata, tmp_path):
    """Elimina grupos duplicados pelo identificador numerico e preserva grupos desconhecidos."""
    parsed_metadata(tls=[_tls(supported_groups=["29", "0x001d", "future-group", "future-group"],
                             key_share_groups=["29"])])
    algorithms = _algorithms(parser.scan(tmp_path / "duplicate-groups.pcap"))
    assert len(algorithms) == 2
    assert {f.algorithm_name for f in algorithms} == {"ECDHE-X25519", "TLS-GROUP-future-group"}

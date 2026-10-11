"""Protocol extraction contracts using independent TShark-shaped observations.

Only the external extraction boundary is mocked. Assertions check provenance,
capabilities versus selections, and ambiguity rather than helper internals.
"""
from __future__ import annotations

import logging
from unittest.mock import Mock

import pytest

from scanner.network_scanner.parser import tshark_parser as parser


@pytest.fixture
def tshark_packets(monkeypatch):
    run = Mock(return_value=[])
    monkeypatch.setattr(parser, "_run_tshark_json", run)

    def set_packets(*layers):
        run.return_value = [{"_source": {"layers": packet}} for packet in layers]
        return run

    return set_packets


@pytest.mark.parametrize("handshake,is_server", [("1", False), (1, False), ("0x01", False),
                                                 ("2", True), (2, True), ("0x02", True)])
def test_tls_only_server_hello_selects_one_cipher_and_share(tshark_packets, handshake, is_server):
    """Verifica que apenas ServerHello atribui cifra e grupo selecionados, preservando os restantes campos TLS."""
    run = tshark_packets({
        "tls.handshake.type": [handshake],
        "tls.handshake.ciphersuite": ["0x1302"],
        "tls.handshake.extensions_supported_group": ["0x001d", "0x11ec"],
        "tls.handshake.extensions_key_share_group": ["0x11ec"],
        "tls.handshake.extensions.supported_version": ["0x0304"],
        "tls.handshake.extensions_server_name": ["service.example"],
        "tls.handshake.sig_hash_alg": ["0x0804", "0x0403"],
    })
    [entry] = parser.extract_tls_metadata("independent.pcap")
    assert entry["handshake_type"] == ("Server Hello" if is_server else "Client Hello")
    assert entry["cipher_suites"] == ["0x1302"]
    assert entry["supported_groups"] == ["0x001d", "0x11ec"]
    assert entry["key_share_groups"] == ["0x11ec"]
    assert entry["signature_algorithms"] == ["0x0804", "0x0403"]
    assert entry["selected_cipher"] == ("0x1302" if is_server else None)
    assert entry["selected_group"] == ("0x11ec" if is_server else None)
    assert entry["server_name"] == "service.example"
    assert entry["tls_version"] == "TLS 1.3"
    assert entry["hello_retry_request"] is False
    args = run.call_args.args
    assert args[0] == "independent.pcap"
    assert "tls.handshake.type" in args[2]
    assert "tls.handshake.extensions_key_share_group" in args[2]


@pytest.mark.parametrize("supported,handshake_version,record_version,expected,expected_supported", [
    (["0x0304"], "0x0303", "0x0301", "TLS 1.3", ["TLS 1.3"]),
    (["0x0302", "0x0304", "0x0303"], "0x0301", "0x0300", "TLS 1.3", ["TLS 1.1", "TLS 1.3", "TLS 1.2"]),
    (["0x0304", "0x0303", "0x0302"], "0x0301", "0x0300", "TLS 1.3", ["TLS 1.3", "TLS 1.2", "TLS 1.1"]),
    (["0x0a0a", "0x0303", "0x2a2a", "0x0304"], "0x0301", "0x0300", "TLS 1.3", ["TLS 1.2", "TLS 1.3"]),
    (["771", "772"], "770", "769", "TLS 1.3", ["TLS 1.2", "TLS 1.3"]),
    ([771, 772], 770, 769, "TLS 1.3", ["TLS 1.2", "TLS 1.3"]),
    ([], "0x0302", "0x0301", "TLS 1.1", []),
    (["0x1a1a"], "0x0303", "0x0301", "TLS 1.2", []),
    ([], None, "0x0300", "SSL 3.0", []),
    ([], None, None, None, []),
])
def test_tls_client_version_priority_and_offered_order(tshark_packets, supported, handshake_version,
                                                      record_version, expected, expected_supported):
    """Verifica a prioridade das fontes da versao TLS, a ordem das versoes anunciadas e a exclusao de GREASE."""
    tshark_packets({"tls.handshake.type": ["1"],
                    "tls.handshake.extensions.supported_version": supported,
                    "tls.handshake.version": handshake_version,
                    "tls.record.version": record_version})
    [entry] = parser.extract_tls_metadata("versions.pcap")
    assert entry["tls_version"] == expected
    assert entry["supported_versions"] == expected_supported
    assert entry["selected_cipher"] is None
    assert entry["selected_group"] is None


@pytest.mark.parametrize("selected_version,expected", [("0x0304", "TLS 1.3"), ("772", "TLS 1.3"),
                                                       (772, "TLS 1.3"), ("0X0303", "TLS 1.2")])
def test_tls_server_selected_version_overrides_legacy_version(tshark_packets, selected_version, expected):
    """Verifica que a versao selecionada no ServerHello tem prioridade sobre versoes legadas do handshake e do registo."""
    tshark_packets({"tls.handshake.type": ["2"],
                    "tls.handshake.version": ["0x0303"],
                    "tls.record.version": ["0x0301"],
                    "tls.handshake.extensions.supported_version": [selected_version]})
    [entry] = parser.extract_tls_metadata("server-version.pcap")
    assert entry["tls_version"] == expected
    assert entry["supported_versions"] == [expected]


@pytest.mark.parametrize("supported,expected,version", [
    (["0x1a1a", "0x0500", "0x0304"], ["0x0500", "TLS 1.3"], "TLS 1.3"),
    (["0x0500"], ["0x0500"], "TLS 1.2"),
    (["1280", "0x0304", "0x0500"], ["1280", "TLS 1.3", "0x0500"], "TLS 1.3"),
    (["malformed", "-1", "65536", "0x1a1a", "0x0500"], ["0x0500"], "TLS 1.2"),
])
def test_tls_unknown_supported_version_survives_without_grease(tshark_packets, supported, expected, version):
    """Preserva versoes anunciadas desconhecidas e a ordem, excluindo GREASE e valores invalidos."""
    tshark_packets({"tls.handshake.type": ["1"],
                    "tls.handshake.version": ["0x0303"],
                    "tls.handshake.extensions.supported_version": supported})
    [entry] = parser.extract_tls_metadata("future-version.pcap")
    assert entry["tls_version"] == version
    # Unrecognized versions are evidence, whereas GREASE is a reserved probe.
    # Dropping the former makes downstream unknown-risk findings impossible.
    assert entry["supported_versions"] == expected


@pytest.mark.parametrize("selected,expected,supported", [
    (["0x0500"], "0x0500", ["0x0500"]),
    (["1280"], "1280", ["1280"]),
    (["0X0500"], "0X0500", ["0X0500"]),
    ([], "TLS 1.2", []),
])
def test_tls_unknown_server_selected_version_is_not_replaced_by_legacy_tls12(tshark_packets, selected, expected, supported):
    """Preserva a selecao desconhecida e usa a versao legada apenas sem extensao."""
    tshark_packets({"tls.handshake.type": ["2"],
                    "tls.handshake.version": ["0x0303"],
                    "tls.handshake.extensions.supported_version": selected})
    [entry] = parser.extract_tls_metadata("future-server-version.pcap")
    assert entry["tls_version"] == expected
    assert entry["supported_versions"] == supported


@pytest.mark.parametrize("extractor,protocol_fields", [
    (parser.extract_tls_metadata, {"tls.handshake.type": ["1"]}),
    (parser.extract_ssh_metadata, {"ssh.protocol": ["SSH-2.0-Independent"]}),
])
@pytest.mark.parametrize("ip_fields,expected_src,expected_dst", [
    ({"ip.src": ["192.0.2.10"], "ip.dst": ["198.51.100.20"]}, "192.0.2.10", "198.51.100.20"),
    ({"ipv6.src": ["2001:db8::10"], "ipv6.dst": ["2001:db8::20"]}, "2001:db8::10", "2001:db8::20"),
])
def test_protocol_packet_stream_and_ipv4_ipv6_provenance(tshark_packets, extractor, protocol_fields,
                                                        ip_fields, expected_src, expected_dst):
    """Preserva pacote, ligacao TCP, timestamp, portas e enderecos IPv4 ou IPv6 na extracao TLS e SSH."""
    run = tshark_packets({**protocol_fields, **ip_fields, "frame.number": ["37"],
                         "frame.time_epoch": ["1777777777.123456"], "tcp.stream": ["9"],
                         "tcp.srcport": ["49152"], "tcp.dstport": ["443"]})
    [entry] = extractor("provenance.pcap")
    assert {key: entry[key] for key in ("packet_number", "stream_id", "timestamp", "source_ip",
                                      "destination_ip", "source_port", "destination_port")} == {
        "packet_number": 37, "stream_id": "9", "timestamp": "1777777777.123456",
        "source_ip": expected_src, "destination_ip": expected_dst,
        "source_port": "49152", "destination_port": "443",
    }
    assert {"frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
            "tcp.srcport", "tcp.dstport"}.issubset(run.call_args.args[2])


@pytest.mark.parametrize("handshake", ["1", "2"])
def test_tls_missing_optional_fields_remain_empty_not_invented(tshark_packets, handshake):
    """Mantem campos opcionais TLS ausentes como None ou listas vazias, sem inventar valores."""
    tshark_packets({"tls.handshake.type": handshake})
    [entry] = parser.extract_tls_metadata("minimal.pcap")
    assert entry["handshake_type"] == ("Client Hello" if handshake == "1" else "Server Hello")
    for field in ("packet_number", "stream_id", "timestamp", "source_ip", "destination_ip", "source_port",
                  "destination_port", "tls_version", "selected_cipher", "selected_group", "server_name"):
        assert entry[field] is None, field
    for field in ("cipher_suites", "supported_groups", "key_share_groups", "signature_algorithms", "supported_versions"):
        assert entry[field] == [], field
    assert entry["hello_retry_request"] is False


@pytest.mark.parametrize("types", [["1", "2"], [1, 2, 11], ["0x01", "0x02"], [], ["11"], ["malformed"]])
def test_tls_ambiguous_or_missing_hello_type_is_logged_and_skipped(tshark_packets, caplog, types):
    """Verifica que tipos de hello ausentes ou ambiguos sao ignorados e originam um aviso com o numero do pacote."""
    tshark_packets({"frame.number": ["41"], "tls.handshake.type": types,
                    "tls.handshake.ciphersuite": ["0x1302"],
                    "tls.handshake.extensions_key_share_group": ["0x11ec"]})
    with caplog.at_level(logging.WARNING, logger=parser.__name__):
        assert parser.extract_tls_metadata("ambiguous.pcap") == []
    messages = [record.getMessage() for record in caplog.records if record.name == parser.__name__]
    assert any("ambiguous" in message.lower() and "41" in message for message in messages)


@pytest.mark.parametrize("ambiguous_types", [["1", "2"], ["2", "2"], ["1", "1"]])
def test_tls_ambiguous_packet_does_not_hide_adjacent_valid_hellos(tshark_packets, caplog, ambiguous_types):
    """Verifica que um pacote TLS ambiguo nao impede extrair os hellos validos adjacentes."""
    tshark_packets(
        {"frame.number": ["1"], "tls.handshake.type": ["1"], "tls.handshake.ciphersuite": ["0x1301"]},
        {"frame.number": ["2"], "tls.handshake.type": ambiguous_types, "tls.handshake.ciphersuite": ["0x1302"]},
        {"frame.number": ["3"], "tls.handshake.type": ["2"], "tls.handshake.ciphersuite": ["0x1303"]},
    )
    with caplog.at_level(logging.WARNING, logger=parser.__name__):
        entries = parser.extract_tls_metadata("mixed.pcap")
    assert [entry["packet_number"] for entry in entries] == [1, 3]
    assert entries[0]["selected_cipher"] is None
    assert entries[1]["selected_cipher"] == "0x1303"


@pytest.mark.parametrize("types", [
    ["2", "2"], [2, 2], ["0x02", "0X02"], ["2", "0x02", 2],
    ["1", "1"], [1, 1], ["0x01", "0X01"], ["1", "0x01", 1],
])
def test_tls_multiple_hellos_in_one_frame_are_logged_and_skipped(tshark_packets, caplog, types):
    """Rejeita Hellos repetidos, mesmo quando usam representacoes numericas diferentes."""
    tshark_packets({"frame.number": ["42"], "tls.handshake.type": types,
                    "tls.handshake.ciphersuite": ["0x1302"],
                    "tls.handshake.extensions_key_share_group": ["0x11ec"]})
    with caplog.at_level(logging.WARNING, logger=parser.__name__):
        assert parser.extract_tls_metadata("repeated-hello.pcap") == []
    assert any("ambiguous" in record.getMessage().lower() and "42" in record.getMessage()
               for record in caplog.records if record.name == parser.__name__)


@pytest.mark.parametrize("types", [["2", "11", "12", "14"], [2, "11", "0x0e"]])
def test_tls_single_server_hello_with_other_messages_preserves_selection(tshark_packets, caplog, types):
    """Preserva um unico ServerHello acompanhado por mensagens que nao sao Hello."""
    tshark_packets({"frame.number": ["43"], "tls.handshake.type": types,
                    "tls.handshake.version": ["0x0303"],
                    "tls.handshake.ciphersuite": ["0xc02f"]})
    with caplog.at_level(logging.WARNING, logger=parser.__name__):
        [entry] = parser.extract_tls_metadata("server-with-certificate.pcap")
    assert entry["packet_number"] == 43
    assert entry["handshake_type"] == "Server Hello"
    assert entry["tls_version"] == "TLS 1.2"
    assert entry["selected_cipher"] == "0xc02f" and entry["selected_group"] is None
    assert not any("ambiguous" in record.getMessage().lower()
                   for record in caplog.records if record.name == parser.__name__)


@pytest.mark.parametrize("field,selected_field", [
    ("tls.handshake.ciphersuite", "selected_cipher"),
    ("tls.handshake.extensions_key_share_group", "selected_group"),
])
@pytest.mark.parametrize("values", [[], [None, ""], ["0x1301", "0x1302"], ["0x1301", "0x1301"]])
def test_tls_server_never_chooses_from_missing_or_multiple_values(tshark_packets, field, selected_field, values):
    """Impede escolher cifra ou grupo no ServerHello quando os valores estao ausentes, repetidos ou sao multiplos."""
    tshark_packets({"tls.handshake.type": ["2"], field: values})
    [entry] = parser.extract_tls_metadata("multiple.pcap")
    assert entry[selected_field] is None


@pytest.mark.parametrize("colon_form,uppercase", [(False, False), (True, False), (True, True)])
def test_tls_hello_retry_request_never_claims_negotiated_cipher_or_group(tshark_packets, colon_form, uppercase):
    # RFC 8446 section 4.1.3 specifies this fixed ServerHello.random value.
    """Reconhece HelloRetryRequest em diferentes representacoes e nao o apresenta como selecao final."""
    retry_random = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
    if colon_form:
        retry_random = ":".join(retry_random[index:index + 2] for index in range(0, 64, 2))
    if uppercase:
        retry_random = retry_random.upper()
    tshark_packets({"tls.handshake.type": ["2"], "tls.handshake.random": [retry_random],
                    "tls.handshake.ciphersuite": ["0x1302"],
                    "tls.handshake.extensions_key_share_group": ["0x11ec"],
                    "tls.handshake.extensions.supported_version": ["0x0304"]})
    [entry] = parser.extract_tls_metadata("retry.pcap")
    assert entry["hello_retry_request"] is True
    assert entry["cipher_suites"] == ["0x1302"]
    assert entry["key_share_groups"] == ["0x11ec"]
    assert entry["selected_cipher"] is None
    assert entry["selected_group"] is None


def test_tls_near_retry_random_remains_a_real_server_selection(tshark_packets):
    """Verifica que um random apenas semelhante ao de HelloRetryRequest continua a representar uma selecao normal."""
    tshark_packets({"tls.handshake.type": ["2"],
                    "tls.handshake.random": ["cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339d"],
                    "tls.handshake.ciphersuite": "0x1301",
                    "tls.handshake.extensions_key_share_group": "29"})
    [entry] = parser.extract_tls_metadata("not-retry.pcap")
    assert entry["hello_retry_request"] is False
    assert entry["selected_cipher"] == "0x1301"
    assert entry["selected_group"] == "29"


@pytest.mark.parametrize("handshake", ["1", "2"])
def test_tls_unrecognized_cipher_group_and_signature_ids_are_preserved(tshark_packets, handshake):
    """Preserva identificadores TLS desconhecidos de cifras, grupos e assinaturas para analise posterior."""
    tshark_packets({"tls.handshake.type": [handshake],
                    "tls.handshake.ciphersuite": ["0xfefe"],
                    "tls.handshake.extensions_supported_group": ["0xfdfd"],
                    "tls.handshake.extensions_key_share_group": ["0xfbfb"],
                    "tls.handshake.sig_hash_alg": ["0xfcfc"]})
    [entry] = parser.extract_tls_metadata("unknown.pcap")
    assert entry["cipher_suites"] == ["0xfefe"]
    assert entry["supported_groups"] == ["0xfdfd"]
    assert entry["key_share_groups"] == ["0xfbfb"]
    assert entry["signature_algorithms"] == ["0xfcfc"]
    assert entry["selected_cipher"] == ("0xfefe" if handshake == "2" else None)
    assert entry["selected_group"] == ("0xfbfb" if handshake == "2" else None)


@pytest.mark.parametrize("cipher,group,signature,expected_cipher,expected_group,expected_signature", [
    (4866, 4588, 2052, "4866", "4588", "2052"),
    ("4866", "4588", "2052", "4866", "4588", "2052"),
    ("0x1302", "0x11ec", "0x0804", "0x1302", "0x11ec", "0x0804"),
])
def test_tls_metadata_preserves_decimal_and_hex_identifier_encodings(tshark_packets, cipher, group,
                                                                   signature, expected_cipher,
                                                                   expected_group, expected_signature):
    """Preserva as representacoes decimais e hexadecimais dos identificadores extraidos do TShark."""
    tshark_packets({"tls.handshake.type": ["2"], "tls.handshake.ciphersuite": [cipher],
                    "tls.handshake.extensions_key_share_group": [group],
                    "tls.handshake.sig_hash_alg": [signature]})
    [entry] = parser.extract_tls_metadata("numeric-identifiers.pcap")
    assert entry["cipher_suites"] == [expected_cipher]
    assert entry["selected_cipher"] == expected_cipher
    assert entry["key_share_groups"] == [expected_group]
    assert entry["selected_group"] == expected_group
    assert entry["signature_algorithms"] == [expected_signature]


_SSH_FIELDS = [
    ("ssh.kex_algorithms", "kex_algorithms"),
    ("ssh.server_host_key_algorithms", "server_host_key_algorithms"),
    ("ssh.encryption_algorithms_client_to_server", "encryption_client_to_server"),
    ("ssh.encryption_algorithms_server_to_client", "encryption_server_to_client"),
    ("ssh.mac_algorithms_client_to_server", "mac_client_to_server"),
    ("ssh.mac_algorithms_server_to_client", "mac_server_to_client"),
]


@pytest.mark.parametrize("wire_field,output_field", _SSH_FIELDS)
@pytest.mark.parametrize("wire_value,expected", [
    ("first,second", ["first", "second"]),
    (["first, second", " third, ,fourth "], ["first", "second", "third", "fourth"]),
    ([None, "", " , , "], []),
    (None, []),
    (["custom@example.org", "unknown-algorithm"], ["custom@example.org", "unknown-algorithm"]),
])
def test_ssh_every_algorithm_field_splits_csv_preserving_offer_order(tshark_packets, wire_field,
                                                                  output_field, wire_value, expected):
    """Divide as listas SSH separadas por virgulas, preserva a ordem e mantem as categorias independentes."""
    tshark_packets({wire_field: wire_value})
    [entry] = parser.extract_ssh_metadata("ssh-lists.pcap")
    assert entry[output_field] == expected
    for _, other_output in _SSH_FIELDS:
        if other_output != output_field:
            assert entry[other_output] == []


@pytest.mark.parametrize("source_port,destination_port,is_server", [
    ("22", "50123", True), (22, 50123, True), ("0x16", "50123", True),
    ("50123", "22", False), (50123, 22, False),
    ("22", "22", None), ("2222", "50123", None),
    (None, None, None), ("invalid", "also-invalid", None),
])
def test_ssh_role_requires_exactly_one_standard_ssh_port(tshark_packets, source_port, destination_port, is_server):
    """So infere o papel SSH pela porta padrao quando exatamente um endpoint usa a porta 22."""
    tshark_packets({"tcp.srcport": source_port, "tcp.dstport": destination_port,
                    "ssh.protocol": ["SSH-2.0-Independent_Test"]})
    [entry] = parser.extract_ssh_metadata("roles.pcap")
    assert entry["is_server"] is is_server
    assert entry["role_source"] == ("standard-port" if is_server is not None else None)
    assert entry["protocol_banner"] == "SSH-2.0-Independent_Test"


def test_ssh_banner_only_does_not_invent_negotiation(tshark_packets):
    """Extrai o banner SSH sem inventar listas de negociacao, papeis ou campos ausentes."""
    tshark_packets({"frame.number": "77", "tcp.stream": "0", "ssh.protocol": "SSH-2.0-Custom"})
    [entry] = parser.extract_ssh_metadata("banner.pcap")
    assert entry["packet_number"] == 77
    assert entry["stream_id"] == "0"
    assert entry["protocol_banner"] == "SSH-2.0-Custom"
    assert entry["is_server"] is None
    assert entry["role_source"] is None
    for _, output_field in _SSH_FIELDS:
        assert entry[output_field] == []
    for field in ("timestamp", "source_ip", "destination_ip", "source_port", "destination_port"):
        assert entry[field] is None


def test_ssh_all_six_lists_and_two_packet_directions_stay_separate(tshark_packets):
    """Mantem separadas as seis categorias de propostas SSH e os registos nas duas direcoes da ligacao."""
    fields = {wire: [f"offer-{index}-a,offer-{index}-b"] for index, (wire, _) in enumerate(_SSH_FIELDS)}
    tshark_packets({**fields, "frame.number": ["18"], "tcp.stream": ["4"],
                    "tcp.srcport": ["49152"], "tcp.dstport": ["22"]},
                   {"frame.number": ["19"], "tcp.stream": ["4"],
                    "tcp.srcport": ["22"], "tcp.dstport": ["49152"],
                    "ssh.kex_algorithms": ["different-server-offer"]})
    client, server = parser.extract_ssh_metadata("directions.pcap")
    assert client["is_server"] is False
    assert server["is_server"] is True
    assert (client["packet_number"], server["packet_number"]) == (18, 19)
    assert client["stream_id"] == server["stream_id"] == "4"
    for index, (_, output) in enumerate(_SSH_FIELDS):
        assert client[output] == [f"offer-{index}-a", f"offer-{index}-b"]
    assert server["kex_algorithms"] == ["different-server-offer"]
    assert server["encryption_client_to_server"] == []


@pytest.mark.parametrize("extractor", [parser.extract_tls_metadata, parser.extract_ssh_metadata])
def test_empty_capture_has_no_protocol_observations(tshark_packets, extractor):
    """Verifica que uma extracao sem pacotes devolve uma lista vazia de observacoes TLS ou SSH."""
    tshark_packets()
    assert extractor("empty.pcap") == []

import copy
import json
from pathlib import Path

import pytest

from scanner.models import AssetType, QuantumRiskLevel
from scanner.network_scanner.analyser.ssh_analyzer import analyze_ssh


PATH = Path("captured.pcap")


def offer(*, server=False, packet=1, stream="0", **kwargs):
    return {
        "source_ip": "10.0.0.2" if server else "10.0.0.1",
        "destination_ip": "10.0.0.1" if server else "10.0.0.2",
        "source_port": "22" if server else "50100",
        "destination_port": "50100" if server else "22",
        "is_server": server, "stream_id": stream, "packet_number": packet,
        **kwargs,
    }


def test_csv_lists_remain_advertised_without_peer_and_rsa_size_is_unknown():
    """Verifica que propostas sem o outro participante permanecem anunciadas e nao inventam tamanhos RSA."""
    findings = analyze_ssh([offer(
        kex_algorithms=["curve25519-sha256,diffie-hellman-group14-sha256,ext-info-c"],
        server_host_key_algorithms=["rsa-sha2-512,ssh-ed25519"],
        encryption_client_to_server=["aes128-cbc,aes256-gcm@openssh.com"],
        mac_client_to_server=["hmac-sha2-256"],
    )], PATH)
    assert len(findings) == 7
    assert {item.observation for item in findings} == {"advertised"}
    assert next(item for item in findings if item.algorithm_name == "RSA").key_size is None
    assert next(item for item in findings if item.algorithm_name == "DHE").key_size == 2048
    assert next(item for item in findings if item.algorithm_name == "HMAC-SHA-256").key_size is None
    assert all(item.evidence[0].packet_number == 1 for item in findings)


def test_selection_uses_client_preference_and_has_evidence_from_both_peers():
    """Verifica a selecao pela preferencia do cliente, com evidencias de ambos os participantes e sem confirmar a conclusao do handshake."""
    client = offer(packet=4, kex_algorithms=["curve25519-sha256,diffie-hellman-group14-sha256"],
                   server_host_key_algorithms=["rsa-sha2-512,ssh-ed25519"],
                   encryption_client_to_server=["aes256-ctr,aes128-cbc"])
    server = offer(server=True, packet=5, kex_algorithms=["diffie-hellman-group14-sha256,curve25519-sha256"],
                   server_host_key_algorithms=["ssh-ed25519,rsa-sha2-512"],
                   encryption_client_to_server=["aes128-cbc,aes256-ctr"])
    selected = [item for item in analyze_ssh([client, server], PATH) if item.observation == "negotiated"]
    assert {item.algorithm_name for item in selected} == {"ECDHE-X25519", "RSA", "AES"}
    assert next(item for item in selected if item.algorithm_name == "AES").mode == "CTR"
    assert next(item for item in selected if item.algorithm_name == "RSA").key_size is None
    assert all(item.confidence == "medium" for item in selected)
    assert all([e.packet_number for e in item.evidence] == [4, 5] for item in selected)
    assert all("completion is not established" in item.evidence[0].risk_reasoning for item in selected)


def test_unknown_roles_or_different_streams_do_not_prove_negotiation():
    """Impede inferir negociacao quando os papeis sao desconhecidos ou as mensagens pertencem a ligacoes diferentes."""
    first = offer(kex_algorithms=["curve25519-sha256"], is_server=None)
    second = offer(server=True, packet=2, kex_algorithms=["curve25519-sha256"], is_server=None)
    assert all(item.observation == "advertised" for item in analyze_ssh([first, second], PATH))
    first["is_server"] = False
    second.update(is_server=True, stream_id="1")
    assert all(item.observation == "advertised" for item in analyze_ssh([first, second], PATH))


def test_aead_does_not_negotiate_independent_hmac():
    """Verifica que uma cifra AEAD nao seleciona um HMAC independente, embora este possa ter sido anunciado."""
    kwargs = {
        "encryption_client_to_server": ["chacha20-poly1305@openssh.com"],
        "mac_client_to_server": ["hmac-sha2-256"],
    }
    findings = analyze_ssh([offer(**kwargs), offer(server=True, packet=2, **kwargs)], PATH)
    selected = [item for item in findings if item.observation == "negotiated"]
    assert len(selected) == 1
    assert selected[0].algorithm_name == "ChaCha20-Poly1305"
    assert any(item.algorithm_name == "HMAC-SHA-256" and item.observation == "advertised" for item in findings)


def test_unknown_algorithms_and_hybrids_are_not_guessed_from_substrings():
    """Reconhece hibridos conhecidos e preserva algoritmos desconhecidos sem inferir propriedades pelo nome."""
    findings = analyze_ssh([offer(kex_algorithms=["mlkem768x25519-sha256,fake-mlkem-sntrup-algorithm"])], PATH)
    known, unknown = findings
    assert known.algorithm_name == "MLKEM768X25519"
    assert known.quantum_risk == QuantumRiskLevel.SAFE
    assert unknown.algorithm_name == "fake-mlkem-sntrup-algorithm"
    assert unknown.quantum_risk == QuantumRiskLevel.UNKNOWN
    assert unknown.key_size is None


def test_banner_is_observed_protocol_without_invented_algorithms():
    """Regista o banner como protocolo observado, sem criar algoritmos ou tamanhos de chave."""
    findings = analyze_ssh([offer(protocol_banner="SSH-2.0-OpenSSH_9.9")], PATH)
    assert len(findings) == 1
    assert findings[0].asset_type == AssetType.PROTOCOL
    assert findings[0].observation == "observed"
    assert findings[0].protocol == "SSH 2.0"
    assert findings[0].key_size is None


def negotiated(entries):
    return [finding for finding in analyze_ssh(entries, PATH) if finding.observation == "negotiated"]


def test_empty_metadata_has_no_findings():
    assert analyze_ssh([], PATH) == []


@pytest.mark.parametrize("stream", [None, "", "  ", True, False, [], {}])
def test_missing_or_invalid_stream_keeps_algorithms_advertised(stream):
    entries = [offer(stream=stream, kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=2, stream=stream, kex_algorithms="curve25519-sha256")]
    assert {finding.observation for finding in analyze_ssh(entries, PATH)} == {"advertised"}


@pytest.mark.parametrize("role", [None, 0, 1, "client", "server"])
def test_role_must_be_an_explicit_boolean(role):
    entries = [offer(is_server=role, kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=2, kex_algorithms="curve25519-sha256")]
    assert negotiated(entries) == []


@pytest.mark.parametrize("client_role,server_role", [(False, False), (True, True), (False, None)])
def test_two_offers_still_require_one_client_and_one_server(client_role, server_role):
    entries = [offer(is_server=client_role, kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=2, is_server=server_role, kex_algorithms="curve25519-sha256")]
    assert negotiated(entries) == []


@pytest.mark.parametrize("changed", [
    {"source_ip": "10.0.0.3"}, {"destination_ip": "10.0.0.3"},
    {"source_port": "2222"}, {"destination_port": "50101"},
])
def test_shared_stream_does_not_pair_different_endpoints(changed):
    entries = [offer(kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=2, kex_algorithms="curve25519-sha256", **changed)]
    assert negotiated(entries) == []


@pytest.mark.parametrize("changed", [
    {"source_ip": None}, {"source_ip": "  "}, {"source_ip": 123},
    {"destination_ip": None}, {"source_port": None}, {"source_port": True},
    {"source_port": 1.5}, {"source_port": ""}, {"source_port": "invalid"},
    {"source_port": 0}, {"source_port": -1}, {"source_port": 65536},
    {"destination_port": None},
])
def test_incomplete_or_invalid_endpoint_does_not_prove_a_peer_pair(changed):
    entries = [offer(kex_algorithms="curve25519-sha256", **changed),
               offer(server=True, packet=2, kex_algorithms="curve25519-sha256")]
    assert negotiated(entries) == []


def test_numeric_stream_and_ports_match_string_representations():
    client = offer(stream=0, source_port=50100, destination_port=" 22 ",
                   kex_algorithms="curve25519-sha256")
    server = offer(server=True, packet=2, source_port=22, destination_port="50100",
                   kex_algorithms="curve25519-sha256")
    [finding] = negotiated([server, client])
    assert finding.algorithm_name == "ECDHE-X25519"
    assert [e.packet_number for e in finding.evidence] == [1, 2]


@pytest.mark.parametrize("extra_offers", [1, 2])
def test_multiple_offers_in_one_stream_are_ambiguous_without_round_identifiers(extra_offers):
    client = offer(kex_algorithms="curve25519-sha256")
    server = offer(server=True, packet=2, kex_algorithms="curve25519-sha256")
    entries = [client, server, offer(packet=3, kex_algorithms="diffie-hellman-group14-sha256")]
    if extra_offers == 2:
        entries.append(offer(server=True, packet=4, kex_algorithms="diffie-hellman-group14-sha256"))
    findings = analyze_ssh(entries, PATH)
    assert {finding.observation for finding in findings} == {"advertised"}
    assert {finding.evidence[0].packet_number for finding in findings} == set(range(1, len(entries) + 1))


def test_retransmitted_offer_does_not_create_a_cartesian_pairing():
    client = offer(kex_algorithms="curve25519-sha256")
    entries = [client, copy.deepcopy(client),
               offer(server=True, packet=2, kex_algorithms="curve25519-sha256")]
    assert negotiated(entries) == []


def test_banner_only_messages_do_not_make_one_kex_pair_ambiguous():
    entries = [offer(protocol_banner="SSH-2.0-Client"),
               offer(server=True, packet=2, protocol_banner="SSH-2.0-Server"),
               offer(packet=3, kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=4, kex_algorithms="curve25519-sha256")]
    findings = analyze_ssh(entries, PATH)
    assert sum(f.observation == "observed" for f in findings) == 2
    [selected] = [f for f in findings if f.observation == "negotiated"]
    assert [e.packet_number for e in selected.evidence] == [3, 4]


def test_marker_only_extra_offer_still_makes_the_stream_ambiguous():
    entries = [offer(kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=2, kex_algorithms="curve25519-sha256"),
               offer(packet=3, kex_algorithms="ext-info-c,kex-strict-c-v00@openssh.com")]
    assert negotiated(entries) == []


def test_each_stream_selects_its_own_client_preference():
    entries = [offer(stream="0", kex_algorithms="curve25519-sha256"),
               offer(stream="1", packet=3, kex_algorithms="diffie-hellman-group14-sha256"),
               offer(server=True, stream="1", packet=4, kex_algorithms="diffie-hellman-group14-sha256"),
               offer(server=True, stream="0", packet=2, kex_algorithms="curve25519-sha256")]
    selected = negotiated(entries)
    assert {f.algorithm_name for f in selected} == {"ECDHE-X25519", "DHE"}
    assert {tuple(e.packet_number for e in f.evidence) for f in selected} == {(1, 2), (3, 4)}


def test_disjoint_algorithm_lists_keep_both_offers_advertised():
    entries = [offer(kex_algorithms="curve25519-sha256"),
               offer(server=True, packet=2, kex_algorithms="diffie-hellman-group14-sha256")]
    findings = analyze_ssh(entries, PATH)
    assert len(findings) == 2
    assert {finding.observation for finding in findings} == {"advertised"}


@pytest.mark.parametrize("field,client_name,server_name", [
    ("kex_algorithms", "curve25519-sha256", "diffie-hellman-group14-sha256"),
    ("server_host_key_algorithms", "ssh-ed25519", "rsa-sha2-512"),
    ("encryption_client_to_server", "aes128-ctr", "aes256-ctr"),
    ("encryption_server_to_client", "aes128-ctr", "aes256-ctr"),
    ("mac_client_to_server", "hmac-sha2-256", "hmac-sha2-512"),
    ("mac_server_to_client", "hmac-sha2-256", "hmac-sha2-512"),
    ("kex_algorithms", "ext-info-c", "ext-info-s"),
])
def test_incompatible_required_list_prevents_other_common_selections(field, client_name, server_name):
    common = {
        "kex_algorithms": "curve25519-sha256",
        "server_host_key_algorithms": "ssh-ed25519",
        "encryption_client_to_server": "aes256-ctr",
        "encryption_server_to_client": "aes256-ctr",
        "mac_client_to_server": "hmac-sha2-256",
        "mac_server_to_client": "hmac-sha2-256",
    }
    entries = [offer(**{**common, field: client_name}),
               offer(server=True, packet=2, **{**common, field: server_name})]
    findings = analyze_ssh(entries, PATH)
    assert findings and all(finding.observation == "advertised" for finding in findings)
    assert {finding.evidence[0].packet_number for finding in findings} == {1, 2}


@pytest.mark.parametrize("cipher", ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"])
@pytest.mark.parametrize("direction", ["client_to_server", "server_to_client"])
def test_disjoint_mac_lists_do_not_prevent_aead_selection(cipher, direction):
    field = f"mac_{direction}"
    common = {f"encryption_{direction}": cipher, "kex_algorithms": "curve25519-sha256"}
    findings = analyze_ssh([
        offer(**common, **{field: "hmac-sha2-256"}),
        offer(server=True, packet=2, **common, **{field: "hmac-sha2-512"}),
    ], PATH)
    selected = [finding for finding in findings if finding.observation == "negotiated"]
    assert len(selected) == 2
    assert all(json.loads(finding.evidence[0].matched_snippet)["ssh_field"] != field for finding in selected)
    assert sum(finding.observation == "advertised" and finding.algorithm_name.startswith("HMAC-")
               for finding in findings) == 2


@pytest.mark.parametrize("cipher", ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
                                    "chacha20-poly1305@openssh.com"])
@pytest.mark.parametrize("direction", ["client_to_server", "server_to_client"])
def test_aead_suppresses_only_the_mac_in_its_selected_direction(cipher, direction):
    opposite = "server_to_client" if direction == "client_to_server" else "client_to_server"
    kwargs = {f"encryption_{direction}": cipher, f"mac_{direction}": "hmac-sha2-256",
              f"encryption_{opposite}": "aes256-ctr", f"mac_{opposite}": "hmac-sha2-512"}
    findings = analyze_ssh([offer(**kwargs), offer(server=True, packet=2, **kwargs)], PATH)
    selected = [f for f in findings if f.observation == "negotiated"]
    selected_fields = {json.loads(f.evidence[0].matched_snippet)["ssh_field"] for f in selected}
    assert selected_fields == {f"encryption_{direction}", f"encryption_{opposite}", f"mac_{opposite}"}
    assert sum(f.algorithm_name == "HMAC-SHA-256" and f.observation == "advertised" for f in findings) == 2


def test_mac_without_a_selected_cipher_remains_advertised():
    client = offer(encryption_client_to_server="aes128-ctr", mac_client_to_server="hmac-sha2-256")
    server = offer(server=True, packet=2, encryption_client_to_server="aes256-ctr",
                   mac_client_to_server="hmac-sha2-256")
    assert negotiated([client, server]) == []
    kwargs = {"mac_server_to_client": "hmac-sha2-512"}
    assert negotiated([offer(**kwargs), offer(server=True, packet=2, **kwargs)]) == []


def test_aead_offer_does_not_suppress_mac_when_a_conventional_cipher_is_selected():
    kwargs = {"encryption_client_to_server": "aes256-ctr,chacha20-poly1305@openssh.com",
              "mac_client_to_server": "hmac-sha2-256"}
    selected = negotiated([offer(**kwargs), offer(server=True, packet=2, **kwargs)])
    assert {finding.algorithm_name for finding in selected} == {"AES", "HMAC-SHA-256"}
    assert next(f for f in selected if f.algorithm_name == "AES").mode == "CTR"


@pytest.mark.parametrize("cipher", ["future-aes256-gcm@openssh.com", "ChaCha20-Poly1305", "AES", "ML-KEM-768"])
def test_unknown_cipher_does_not_prove_a_separate_mac_or_aead(cipher):
    kwargs = {"encryption_client_to_server": cipher,
              "mac_client_to_server": "hmac-sha2-256"}
    findings = analyze_ssh([offer(**kwargs), offer(server=True, packet=2, **kwargs)], PATH)
    [selected] = [f for f in findings if f.observation == "negotiated"]
    assert selected.algorithm_name == cipher
    assert selected.quantum_risk == selected.classical_risk == QuantumRiskLevel.UNKNOWN
    assert selected.key_size is None and selected.mode is None
    assert sum(f.algorithm_name == "HMAC-SHA-256" and f.observation == "advertised" for f in findings) == 2


@pytest.mark.parametrize("field,wire_name", [
    ("kex_algorithms", "ML-KEM-768"), ("kex_algorithms", "SHA-256"),
    ("kex_algorithms", "Ed25519"), ("server_host_key_algorithms", "Ed25519"),
    ("encryption_client_to_server", "SHA-256"),
    ("encryption_server_to_client", "ChaCha20-Poly1305"),
    ("mac_client_to_server", "HMAC-SHA-256"), ("mac_server_to_client", "SHA-256"),
])
def test_unknown_wire_names_cannot_borrow_the_risk_of_a_canonical_primitive(field, wire_name):
    [advertised] = analyze_ssh([offer(**{field: wire_name})], PATH)
    assert advertised.algorithm_name == wire_name
    assert advertised.quantum_risk == advertised.classical_risk == QuantumRiskLevel.UNKNOWN
    assert advertised.key_size is None
    assert "no verified mapping" in advertised.evidence[0].risk_reasoning
    assert advertised.recommendation

    kwargs = {field: wire_name}
    if field.startswith("mac_"):
        kwargs[field.replace("mac_", "encryption_", 1)] = "aes256-ctr"
    selected = negotiated([offer(**kwargs), offer(server=True, packet=2, **kwargs)])
    unknown = next(f for f in selected if json.loads(f.evidence[0].matched_snippet)["ssh_field"] == field)
    assert unknown.algorithm_name == wire_name
    assert unknown.quantum_risk == unknown.classical_risk == QuantumRiskLevel.UNKNOWN
    assert all("no verified mapping" in e.risk_reasoning for e in unknown.evidence)
    assert all("completion is not established" in e.risk_reasoning for e in unknown.evidence)


def test_names_are_case_sensitive_and_markers_are_not_algorithm_choices():
    entries = [offer(kex_algorithms="ext-info-c,curve25519-sha256"),
               offer(server=True, packet=2, kex_algorithms="ext-info-s,CURVE25519-SHA256")]
    findings = analyze_ssh(entries, PATH)
    assert len(findings) == 2
    assert negotiated(entries) == []
    assert {f.algorithm_name for f in findings} == {"ECDHE-X25519", "CURVE25519-SHA256"}


def test_identical_primitives_in_each_direction_keep_distinct_findings():
    kwargs = {"encryption_client_to_server": "aes256-ctr", "encryption_server_to_client": "aes256-ctr"}
    selected = negotiated([offer(**kwargs), offer(server=True, packet=2, **kwargs)])
    assert len(selected) == 2
    assert {json.loads(f.evidence[0].matched_snippet)["ssh_field"] for f in selected} == {
        "encryption_client_to_server", "encryption_server_to_client",
    }


def test_selection_preserves_inputs_and_independent_advertised_evidence():
    entries = [offer(kex_algorithms="curve25519-sha256", payload="password=SECRET"),
               offer(server=True, packet=2, kex_algorithms="curve25519-sha256", matched_snippet="SECRET")]
    before = copy.deepcopy(entries)
    findings = analyze_ssh(entries, PATH)
    selected = next(f for f in findings if f.observation == "negotiated")
    advertised = [f for f in findings if f.observation == "advertised"]
    assert entries == before
    assert all("completion is not established" in e.risk_reasoning for e in selected.evidence)
    assert all("completion is not established" not in f.evidence[0].risk_reasoning for f in advertised)
    assert all("SECRET" not in e.matched_snippet for f in findings for e in f.evidence)
    selected.evidence[0].risk_reasoning = "Modified selected result"
    assert all(f.evidence[0].risk_reasoning != "Modified selected result" for f in advertised)

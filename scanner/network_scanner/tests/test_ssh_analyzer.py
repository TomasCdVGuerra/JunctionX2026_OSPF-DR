from pathlib import Path

from scanner.models import AssetType, QuantumRiskLevel
from scanner.network_scanner.cleartext_analyzer import analyze_cleartext
from scanner.network_scanner.ssh_analyzer import analyze_ssh


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
    assert next(item for item in findings if item.algorithm_name == "DH").key_size == 2048
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
    assert {item.algorithm_name for item in selected} == {"ECDH", "RSA", "AES"}
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


def test_cleartext_preserves_packet_and_endpoints_but_excludes_credentials():
    """Preserva pacote e endpoints na evidencia de trafego em claro, excluindo credenciais e conteudo sensivel."""
    entry = offer(packet=8, protocol="HTTP", http_method="GET",
                  http_host="username:secret@example.com", http_uri="/login?token=secret",
                  matched_snippet="Authorization: Bearer secret", payload="password=secret")
    finding = analyze_cleartext([entry], PATH)[0]
    assert finding.algorithm_name == "Cleartext"
    assert finding.asset_type == AssetType.PROTOCOL
    assert finding.classical_risk == QuantumRiskLevel.CRITICAL
    assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
    assert finding.evidence[0].file_path == str(PATH)
    assert finding.evidence[0].packet_number == 8
    snippet = finding.evidence[0].matched_snippet
    assert "10.0.0.1:50100 -> 10.0.0.2:22" in snippet
    assert "host=example.com" in snippet
    assert "secret" not in snippet and "username" not in snippet and "token" not in snippet


def test_cleartext_requires_protocol_evidence_not_a_standard_port():
    """Exige evidencia do protocolo para identificar trafego em claro, em vez de usar apenas a porta."""
    assert analyze_cleartext([offer(destination_port="80")], PATH) == []
    for protocol in ["PostgreSQL", "LDAP", "FTP", "Telnet", "SMTP"]:
        findings = analyze_cleartext([offer(protocol=protocol, matched_snippet="PASS secret")], PATH)
        assert findings[0].protocol == protocol
        assert "secret" not in findings[0].evidence[0].matched_snippet

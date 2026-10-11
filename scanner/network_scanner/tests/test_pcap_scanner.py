import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.models import AssetType, CryptoFinding
from scanner.models import QuantumRiskLevel as Q
from scanner.network_scanner import pcap_scanner
from scanner.network_scanner.parser import tshark_parser
from scanner.network_scanner.parser.tshark_parser import (
    PcapParserError,
    _normalize_tls_version,
    detect_cleartext_traffic,
    extract_ssh_metadata,
    extract_tls_metadata,
)


def test_missing_pcap_file():
    """Verifica que uma captura inexistente origina PcapParserError com uma mensagem de ficheiro nao encontrado."""
    with pytest.raises(PcapParserError) as exc_info:
        extract_tls_metadata("caminho_inexistente.pcap")
    assert "não encontrado" in str(exc_info.value)

def test_normalize_tls_version():
    """Converte versoes TLS conhecidas para nomes legiveis e preserva valores desconhecidos ou ausentes."""
    assert _normalize_tls_version("0x0303") == "TLS 1.2"
    assert _normalize_tls_version("0x0304") == "TLS 1.3"
    assert _normalize_tls_version("0x0301") == "TLS 1.0"
    assert _normalize_tls_version("custom") == "custom"
    assert _normalize_tls_version(None) is None

@patch("scanner.network_scanner.parser.tshark_parser.os.path.isfile", return_value=True)
@patch("scanner.network_scanner.parser.tshark_parser._run_tshark_json")
def test_extract_tls_metadata_client_and_server_hello(mock_run, mock_isfile):
    """Extrai campos do ClientHello e ServerHello, distinguindo cifras anunciadas da cifra selecionada pelo servidor."""
    mock_run.return_value = [
        {
            "_source": {
                "layers": {
                    "ip.src": ["192.168.1.50"],
                    "ip.dst": ["10.0.0.1"],
                    "tcp.srcport": ["54321"],
                    "tcp.dstport": ["443"],
                    "tls.handshake.type": ["1"],
                    "tls.handshake.extensions.supported_version": ["0x0304"],
                    "tls.handshake.ciphersuite": ["0x1301", "0x1302", "0xc02f"],
                    "tls.handshake.extensions_supported_group": ["0x001d", "0x6399"],
                    "tls.handshake.extensions_server_name": ["api.example.com"],
                    "tls.handshake.sig_hash_alg": ["0x0403", "0x0804"]
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "ip.src": ["10.0.0.1"],
                    "ip.dst": ["192.168.1.50"],
                    "tcp.srcport": ["443"],
                    "tcp.dstport": ["54321"],
                    "tls.handshake.type": ["2"],
                    "tls.handshake.version": ["0x0303"],
                    "tls.handshake.ciphersuite": ["0x1301"]
                }
            }
        }
    ]

    results = extract_tls_metadata("dummy.pcap")
    assert len(results) == 2

    # Client Hello
    ch = results[0]
    assert ch["source_ip"] == "192.168.1.50"
    assert ch["destination_ip"] == "10.0.0.1"
    assert ch["handshake_type"] == "Client Hello"
    assert ch["tls_version"] == "TLS 1.3"
    assert len(ch["cipher_suites"]) == 3
    assert ch["selected_cipher"] is None
    assert ch["server_name"] == "api.example.com"
    assert "0x6399" in ch["supported_groups"]

    # Server Hello
    sh = results[1]
    assert sh["handshake_type"] == "Server Hello"
    assert sh["selected_cipher"] == "0x1301"

@patch("scanner.network_scanner.parser.tshark_parser.os.path.isfile", return_value=True)
@patch("scanner.network_scanner.parser.tshark_parser._run_tshark_json")
def test_extract_ssh_metadata(mock_run, mock_isfile):
    """Extrai o banner SSH e as listas anunciadas de troca de chaves e algoritmos de chave do servidor."""
    mock_run.return_value = [
        {
            "_source": {
                "layers": {
                    "ip.src": ["192.168.1.10"],
                    "ip.dst": ["192.168.1.20"],
                    "tcp.srcport": ["22"],
                    "tcp.dstport": ["51234"],
                    "ssh.protocol": ["SSH-2.0-OpenSSH_8.9p1"],
                    "ssh.kex_algorithms": ["curve25519-sha256", "diffie-hellman-group14-sha256"],
                    "ssh.server_host_key_algorithms": ["rsa-sha2-512", "ssh-ed25519"]
                }
            }
        }
    ]

    results = extract_ssh_metadata("dummy.pcap")
    assert len(results) == 1
    ssh = results[0]
    assert ssh["protocol_banner"] == "SSH-2.0-OpenSSH_8.9p1"
    assert "curve25519-sha256" in ssh["kex_algorithms"]
    assert "rsa-sha2-512" in ssh["server_host_key_algorithms"]

@patch("scanner.network_scanner.parser.tshark_parser.os.path.isfile", return_value=True)
@patch("scanner.network_scanner.parser.tshark_parser._run_tshark_json")
def test_detect_cleartext_traffic(mock_run, mock_isfile):
    """Identifica um pedido HTTP descodificado e preserva o metodo e o host nos metadados."""
    mock_run.return_value = [
        {
            "_source": {
                "layers": {
                    "ip.src": ["192.168.1.15"],
                    "ip.dst": ["93.184.216.34"],
                    "tcp.srcport": ["49152"],
                    "tcp.dstport": ["80"],
                    "http.request.method": ["GET"],
                    "http.host": ["example.com"],
                    "http.request.uri": ["/index.html"]
                }
            }
        }
    ]

    results = detect_cleartext_traffic("dummy.pcap")
    assert len(results) == 1
    ct = results[0]
    assert ct["protocol"] == "HTTP"
    assert ct["http_method"] == "GET"
    assert ct["http_host"] == "example.com"


def test_scan_mixed_capture_assesses_protocols_from_one_read_without_mutating_metadata(monkeypatch, tmp_path):
    """Passa metadados pelos analisadores reais e preserva selecoes e evidencias."""
    metadata = {
        "tls_sessions": [
            {"packet_number": 10, "stream_id": "1", "handshake_type": "Client Hello",
             "tls_version": "TLS 1.3", "supported_versions": ["TLS 1.3"],
             "cipher_suites": ["0x1301", "0x1302"], "supported_groups": ["29", "4588"]},
            {"packet_number": 11, "stream_id": "1", "handshake_type": "Server Hello",
             "tls_version": "TLS 1.3", "selected_cipher": "0x1302", "selected_group": "4588"},
        ],
        "ssh_sessions": [
            {"packet_number": 20, "stream_id": "2", "is_server": False,
             "source_ip": "192.0.2.1", "destination_ip": "198.51.100.2",
             "source_port": "50123", "destination_port": "22",
             "kex_algorithms": ["curve25519-sha256"], "payload": "SECRET"},
            {"packet_number": 21, "stream_id": "2", "is_server": True,
             "source_ip": "198.51.100.2", "destination_ip": "192.0.2.1",
             "source_port": "22", "destination_port": "50123",
             "kex_algorithms": ["curve25519-sha256"]},
        ],
        "cleartext_traffic": [
            {"packet_number": 30, "protocol": "HTTP", "http_method": "GET",
             "http_host": "user:SECRET@example.test", "payload": "SECRET"},
        ],
    }
    before = copy.deepcopy(metadata)
    parsed_paths = []

    def parse_capture(filepath):
        parsed_paths.append(filepath)
        return metadata

    monkeypatch.setattr(pcap_scanner, "parse_network_pcap", parse_capture)
    path = tmp_path / "mixed capture.pcap"
    findings = pcap_scanner.scan(path)
    assert parsed_paths == [str(path)]
    assert metadata == before
    assert findings and all(isinstance(finding, CryptoFinding) for finding in findings)
    assert all(finding.recommendation and all(evidence.risk_reasoning for evidence in finding.evidence)
               for finding in findings)

    tls = [finding for finding in findings if finding.protocol == "TLS 1.3"]
    advertised_aes = [finding for finding in tls
                      if finding.algorithm_name == "AES" and finding.observation == "advertised"]
    assert {(finding.key_size, finding.quantum_risk) for finding in advertised_aes} == {
        (128, Q.MEDIUM), (256, Q.SAFE),
    }
    [selected_aes] = [finding for finding in tls
                      if finding.algorithm_name == "AES" and finding.observation == "negotiated"]
    assert selected_aes.key_size == 256 and selected_aes.classical_risk == Q.SAFE
    assert selected_aes.evidence[0].packet_number == 11
    [hybrid] = [finding for finding in tls
                if finding.algorithm_name == "X25519MLKEM768" and finding.observation == "negotiated"]
    assert hybrid.quantum_risk == Q.SAFE and hybrid.key_size is None
    versions = [finding for finding in tls if finding.asset_type == AssetType.PROTOCOL]
    assert versions and all(finding.quantum_risk == finding.classical_risk == Q.UNKNOWN
                            for finding in versions)

    ssh = [finding for finding in findings if finding.protocol == "SSH"]
    assert [finding.observation for finding in ssh].count("advertised") == 2
    [selected_ssh] = [finding for finding in ssh if finding.observation == "negotiated"]
    assert selected_ssh.algorithm_name == "ECDHE-X25519"
    assert selected_ssh.quantum_risk == Q.CRITICAL and selected_ssh.confidence == "medium"
    assert [evidence.packet_number for evidence in selected_ssh.evidence] == [20, 21]
    assert all("completion is not established" in evidence.risk_reasoning
               for evidence in selected_ssh.evidence)

    [cleartext] = [finding for finding in findings if finding.algorithm_name == "Cleartext"]
    assert cleartext.observation == "observed" and cleartext.protocol == "HTTP"
    assert (cleartext.quantum_risk, cleartext.classical_risk) == (Q.UNKNOWN, Q.CRITICAL)
    assert json.loads(cleartext.evidence[0].matched_snippet)["http_host"] == "example.test"
    for finding in findings:
        assert all(evidence.file_path == str(path) for evidence in finding.evidence)
        payload = finding.to_dict()
        assert "SECRET" not in json.dumps(payload)
        assert CryptoFinding.model_validate(payload) == finding


@pytest.mark.parametrize("metadata,names", [
    ({}, set()),
    ({"tls_sessions": [], "ssh_sessions": [], "cleartext_traffic": []}, set()),
    ({"cleartext_traffic": [{"protocol": "HTTP"}]}, {"Cleartext"}),
    ({"tls_sessions": [{"handshake_type": "Server Hello", "tls_version": "TLS 1.0"}]}, {"TLS 1.0"}),
    ({"ssh_sessions": [{"protocol_banner": "SSH-2.0-Server"}]}, {"SSH"}),
])
def test_scan_accepts_empty_and_partial_protocol_metadata(monkeypatch, metadata, names):
    monkeypatch.setattr(pcap_scanner, "parse_network_pcap", lambda _: metadata)
    findings = pcap_scanner.scan(Path("partial.pcap"))
    assert {finding.algorithm_name for finding in findings} == names
    assert all(finding.evidence[0].risk_reasoning for finding in findings)


def test_scan_preserves_parser_error_and_does_not_assess_partial_results(monkeypatch):
    failure = PcapParserError("Capture could not be parsed")

    def fail_parsing(_):
        raise failure

    def unexpected_analysis(*_):
        pytest.fail("A failed parse must not produce a partial assessment")

    monkeypatch.setattr(pcap_scanner, "parse_network_pcap", fail_parsing)
    monkeypatch.setattr(pcap_scanner, "analyze_tls", unexpected_analysis)
    monkeypatch.setattr(pcap_scanner, "analyze_ssh", unexpected_analysis)
    monkeypatch.setattr(pcap_scanner, "analyze_cleartext", unexpected_analysis)
    with pytest.raises(PcapParserError) as caught:
        pcap_scanner.scan(Path("broken.pcap"))
    assert caught.value is failure


def test_assessed_scan_keeps_existing_parser_and_json_extraction_contract(monkeypatch):
    metadata = {"cleartext_traffic": [{"protocol": "HTTP", "packet_number": 5}]}
    monkeypatch.setattr(pcap_scanner, "parse_network_pcap", lambda _: metadata)
    monkeypatch.setattr(tshark_parser, "parse_network_pcap", lambda _: metadata)
    path = Path("contracts.pcap")
    [raw] = tshark_parser.scan(path)
    assert raw.quantum_risk == raw.classical_risk == Q.UNKNOWN
    assert raw.recommendation is None and raw.evidence[0].risk_reasoning is None
    assert json.loads(tshark_parser.parse_network_json(path)) == [raw.to_dict()]

    [assessed] = pcap_scanner.scan(str(path))
    assert (assessed.quantum_risk, assessed.classical_risk) == (Q.UNKNOWN, Q.CRITICAL)
    assert assessed.evidence[0].packet_number == 5 and assessed.evidence[0].file_path == str(path)
    assert assessed.evidence[0].risk_reasoning and assessed.recommendation

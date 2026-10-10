import pytest
from unittest.mock import patch
from scanner.network_scanner.parser.tshark_parser import (
    PcapParserError,
    extract_tls_metadata,
    extract_ssh_metadata,
    detect_cleartext_traffic,
    parse_network_pcap,
    _normalize_tls_version
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

import subprocess
import json
import os
import shutil
from typing import List, Dict, Any, Optional

class PcapParserError(Exception):
    """Exceção customizada para identificar erros específicos do parser de PCAP."""
    pass

def find_tshark_binary() -> str:
    """
    Localiza o binário do tshark no PATH do sistema operativo.
    Compatível com Windows, Linux e macOS.
    """
    tshark = shutil.which("tshark")
    if not tshark:
        raise PcapParserError(
            "Erro Crítico: O 'tshark' não foi encontrado. "
            "Instala o Wireshark e garante que está no PATH do sistema."
        )
    return tshark

def _run_tshark_json(pcap_filepath: str, display_filter: str, fields: List[str]) -> List[Dict[str, Any]]:
    """
    Executa o tshark com um filtro de exibição e extrai os campos pedidos em JSON.
    """
    if not os.path.isfile(pcap_filepath):
        raise PcapParserError(f"Ficheiro PCAP não encontrado: {pcap_filepath}")

    tshark_bin = find_tshark_binary()

    command = [
        tshark_bin,
        "-r", pcap_filepath,
        "-Y", display_filter,
        "-T", "json"
    ]
    for field in fields:
        command.extend(["-e", field])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        if not result.stdout.strip():
            return []
        return json.loads(result.stdout)
    except FileNotFoundError:
        raise PcapParserError(
            "Erro Crítico: O 'tshark' não foi encontrado. "
            "Certifica-te de que o Wireshark está instalado e no PATH do sistema."
        )
    except subprocess.CalledProcessError as e:
        raise PcapParserError(f"Erro ao executar o tshark: {e.stderr.strip() if e.stderr else str(e)}")
    except json.JSONDecodeError as e:
        raise PcapParserError(f"Erro a interpretar o resultado do tshark: {e}")

def _get_field_first(layers: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """Retorna o primeiro valor encontrado para uma lista de chaves alternativas (ex: ip.src vs ipv6.src)."""
    for key in keys:
        if key in layers and layers[key]:
            val = layers[key]
            return val[0] if isinstance(val, list) else val
    return default

def _get_field_list(layers: Dict[str, Any], key: str) -> List[str]:
    """Retorna uma lista de strings garantida para a chave especificada."""
    val = layers.get(key, [])
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)] if val is not None else []

def _normalize_tls_version(version_raw: Optional[str]) -> Optional[str]:
    """Traduz códigos de versão TLS conhecidos para nomes legíveis."""
    if not version_raw:
        return None
    version_map = {
        "0x0300": "SSL 3.0", "768": "SSL 3.0",
        "0x0301": "TLS 1.0", "769": "TLS 1.0",
        "0x0302": "TLS 1.1", "770": "TLS 1.1",
        "0x0303": "TLS 1.2", "771": "TLS 1.2",
        "0x0304": "TLS 1.3", "772": "TLS 1.3"
    }
    return version_map.get(version_raw.lower(), version_raw)

def extract_tls_metadata(pcap_filepath: str) -> List[Dict[str, Any]]:
    """
    Extrai metadados completos de sessões TLS:
    - Handshake type (Client Hello vs Server Hello)
    - Versão TLS negociada/proposta
    - Cipher suites (propostas no Client Hello e selecionada no Server Hello)
    - Grupos suportados (Elliptic curves / PQC Key Exchange)
    - SNI (Server Name Indication)
    - Algoritmos de assinatura (Signature Algorithms)
    - IPs e portas de origem e destino
    """
    print(f"[*] A analisar metadados TLS no ficheiro: {pcap_filepath}")

    fields = [
        "frame.time_epoch",
        "ip.src", "ip.dst",
        "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport",
        "tls.handshake.type",
        "tls.record.version",
        "tls.handshake.version",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.ciphersuite",
        "tls.handshake.extensions_supported_group",
        "tls.handshake.extensions_server_name",
        "tls.handshake.sig_hash_alg"
    ]

    # Foco em Client Hello (1) e Server Hello (2)
    display_filter = "tls.handshake.type in {1, 2}"
    pacotes = _run_tshark_json(pcap_filepath, display_filter, fields)
    extracted_data = []

    handshake_names = {
        "1": "Client Hello",
        "2": "Server Hello"
    }

    for pacote in pacotes:
        layers = pacote.get("_source", {}).get("layers", {})

        src_ip = _get_field_first(layers, ["ip.src", "ipv6.src"], "N/A")
        dst_ip = _get_field_first(layers, ["ip.dst", "ipv6.dst"], "N/A")
        src_port = _get_field_first(layers, ["tcp.srcport"], "N/A")
        dst_port = _get_field_first(layers, ["tcp.dstport"], "N/A")
        timestamp = _get_field_first(layers, ["frame.time_epoch"])

        hs_type_raw = _get_field_first(layers, ["tls.handshake.type"])
        hs_type_name = handshake_names.get(str(hs_type_raw), f"Handshake({hs_type_raw})")

        # Versão: dá prioridade a supported_version (TLS 1.3), depois handshake version, depois record
        supp_versions = _get_field_list(layers, "tls.handshake.extensions.supported_version")
        tls_version_raw = supp_versions[0] if supp_versions else _get_field_first(
            layers, ["tls.handshake.version", "tls.record.version"]
        )
        tls_version = _normalize_tls_version(tls_version_raw)

        ciphers = _get_field_list(layers, "tls.handshake.ciphersuite")
        groups = _get_field_list(layers, "tls.handshake.extensions_supported_group")
        server_name = _get_field_first(layers, ["tls.handshake.extensions_server_name"])
        sig_algs = _get_field_list(layers, "tls.handshake.sig_hash_alg")

        entry = {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "handshake_type": hs_type_name,
            "tls_version": tls_version,
            "cipher_suites": ciphers,
            "selected_cipher": ciphers[0] if (hs_type_raw == "2" and ciphers) else None,
            "supported_groups": groups,
            "server_name": server_name,
            "signature_algorithms": sig_algs
        }
        extracted_data.append(entry)

    return extracted_data

def extract_ssh_metadata(pcap_filepath: str) -> List[Dict[str, Any]]:
    """
    Extrai metadados criptográficos de sessões SSH:
    - Banners de versão do protocolo (ex: SSH-2.0-OpenSSH...)
    - Algoritmos de Key Exchange (KEX)
    - Algoritmos de Chave de Servidor (Host Key)
    - Cifras de encriptação cliente->servidor e servidor->cliente
    - MACs negociados
    """
    print(f"[*] A analisar sessões SSH no ficheiro: {pcap_filepath}")

    fields = [
        "frame.time_epoch",
        "ip.src", "ip.dst",
        "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport",
        "ssh.protocol",
        "ssh.kex_algorithms",
        "ssh.server_host_key_algorithms",
        "ssh.encryption_algorithms_client_to_server",
        "ssh.encryption_algorithms_server_to_client",
        "ssh.mac_algorithms_client_to_server",
        "ssh.mac_algorithms_server_to_client"
    ]

    # Filtra pacotes com metadados ou negociação SSH
    display_filter = "ssh.protocol or ssh.kex_algorithms"
    pacotes = _run_tshark_json(pcap_filepath, display_filter, fields)
    extracted_data = []

    for pacote in pacotes:
        layers = pacote.get("_source", {}).get("layers", {})

        src_ip = _get_field_first(layers, ["ip.src", "ipv6.src"], "N/A")
        dst_ip = _get_field_first(layers, ["ip.dst", "ipv6.dst"], "N/A")
        src_port = _get_field_first(layers, ["tcp.srcport"], "N/A")
        dst_port = _get_field_first(layers, ["tcp.dstport"], "N/A")
        timestamp = _get_field_first(layers, ["frame.time_epoch"])

        protocol_banner = _get_field_first(layers, ["ssh.protocol"])
        kex_algs = _get_field_list(layers, "ssh.kex_algorithms")
        host_keys = _get_field_list(layers, "ssh.server_host_key_algorithms")
        enc_c2s = _get_field_list(layers, "ssh.encryption_algorithms_client_to_server")
        enc_s2c = _get_field_list(layers, "ssh.encryption_algorithms_server_to_client")
        mac_c2s = _get_field_list(layers, "ssh.mac_algorithms_client_to_server")
        mac_s2c = _get_field_list(layers, "ssh.mac_algorithms_server_to_client")

        extracted_data.append({
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol_banner": protocol_banner,
            "kex_algorithms": kex_algs,
            "server_host_key_algorithms": host_keys,
            "encryption_client_to_server": enc_c2s,
            "encryption_server_to_client": enc_s2c,
            "mac_client_to_server": mac_c2s,
            "mac_server_to_client": mac_s2c
        })

    return extracted_data

def detect_cleartext_traffic(pcap_filepath: str) -> List[Dict[str, Any]]:
    """
    Identifica fluxos em texto claro (inseguros / sem cifra):
    - HTTP, LDAP sem SSL, Telnet, FTP ou tráfego sem TLS.
    """
    print(f"[*] A analisar tráfego não encriptado (cleartext) no ficheiro: {pcap_filepath}")

    fields = [
        "frame.time_epoch",
        "ip.src", "ip.dst",
        "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport",
        "http.request.method",
        "http.host",
        "http.request.uri"
    ]

    # Portas padrão de protocolos claros ou pedidos HTTP explícitos
    display_filter = "http.request or tcp.dstport in {80, 21, 23, 389}"
    pacotes = _run_tshark_json(pcap_filepath, display_filter, fields)
    extracted_data = []

    for pacote in pacotes:
        layers = pacote.get("_source", {}).get("layers", {})

        src_ip = _get_field_first(layers, ["ip.src", "ipv6.src"], "N/A")
        dst_ip = _get_field_first(layers, ["ip.dst", "ipv6.dst"], "N/A")
        src_port = _get_field_first(layers, ["tcp.srcport"], "N/A")
        dst_port = _get_field_first(layers, ["tcp.dstport"], "N/A")
        timestamp = _get_field_first(layers, ["frame.time_epoch"])

        protocol_hint = "HTTP" if "80" in [src_port, dst_port] or layers.get("http.request.method") else (
            "LDAP" if "389" in [src_port, dst_port] else (
                "FTP" if "21" in [src_port, dst_port] else (
                    "Telnet" if "23" in [src_port, dst_port] else "Cleartext TCP"
                )
            )
        )

        extracted_data.append({
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol_hint,
            "http_method": _get_field_first(layers, ["http.request.method"]),
            "http_host": _get_field_first(layers, ["http.host"]),
            "http_uri": _get_field_first(layers, ["http.request.uri"])
        })

    return extracted_data

def parse_network_pcap(pcap_filepath: str) -> Dict[str, Any]:
    """
    Orquestra a análise global do ficheiro PCAP:
    Retorna metadados consolidados de TLS, SSH e tráfego em texto limpo.
    """
    return {
        "pcap_file": pcap_filepath,
        "tls_sessions": extract_tls_metadata(pcap_filepath),
        "ssh_sessions": extract_ssh_metadata(pcap_filepath),
        "cleartext_traffic": detect_cleartext_traffic(pcap_filepath)
    }

if __name__ == "__main__":
    # Teste rápido executando contra a captura de rede do desafio
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_test_file = os.path.normpath(
        os.path.join(current_dir, "../../../support-materials/network-capture/network.pcap")
    )

    try:
        resultado_global = parse_network_pcap(pcap_test_file)
        tls_total = len(resultado_global["tls_sessions"])
        ssh_total = len(resultado_global["ssh_sessions"])
        cleartext_total = len(resultado_global["cleartext_traffic"])

        print(f"\n[+] Análise concluída com sucesso:")
        print(f"  - Pacotes TLS analisados: {tls_total}")
        print(f"  - Sessões SSH detetadas: {ssh_total}")
        print(f"  - Tráfego em texto limpo: {cleartext_total}")

        if tls_total > 0:
            print(f"\nExemplo de pacote TLS:\n{json.dumps(resultado_global['tls_sessions'][0], indent=2)}")

        if ssh_total > 0:
            print(f"\nExemplo de pacote SSH:\n{json.dumps(resultado_global['ssh_sessions'][0], indent=2)}")

    except Exception as e:
        print(f"\n[-] Erro na execução do parser: {e}")
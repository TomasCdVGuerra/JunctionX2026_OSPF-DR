"""Exercise process boundaries, executable discovery and malformed outputs."""


from __future__ import annotations

import json
import logging
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scanner.network_scanner.parser import tshark_parser as parser


@pytest.fixture
def capture(tmp_path):
    path = tmp_path / "capture with spaces; literal.pcap"
    path.write_bytes(b"test input")
    return path


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.setattr(parser, "find_tshark_binary", lambda: "path with spaces/tshark")
    process = Mock(return_value=subprocess.CompletedProcess([], 0, "[]", ""))
    monkeypatch.setattr(parser.subprocess, "run", process)
    return process


@pytest.mark.parametrize("resolve_on_path", [False, True])
def test_explicit_tshark_configuration_has_precedence(tmp_path, monkeypatch, resolve_on_path):
    """Verifica que TSHARK_PATH tem prioridade, quer indique um caminho quer um nome resolvido no PATH."""
    executable = tmp_path / "custom tshark.exe"
    executable.touch()
    configured = "custom-tshark" if resolve_on_path else str(executable)
    monkeypatch.setenv("TSHARK_PATH", configured)
    which = Mock(return_value=str(executable) if resolve_on_path else None)
    monkeypatch.setattr(parser.shutil, "which", which)
    assert parser.find_tshark_binary() == str(executable)
    which.assert_called_once_with(configured)


def test_invalid_explicit_binary_does_not_silently_use_another(tmp_path, monkeypatch):
    """Exige erro quando o executavel configurado e invalido, sem usar silenciosamente outro TShark."""
    monkeypatch.setenv("TSHARK_PATH", str(tmp_path / "missing.exe"))
    which = Mock(return_value=None)
    monkeypatch.setattr(parser.shutil, "which", which)
    with pytest.raises(parser.PcapParserError, match="TSHARK_PATH"):
        parser.find_tshark_binary()
    assert which.call_count == 1


def test_path_binary_is_used_before_installation_fallbacks(monkeypatch):
    """Verifica que o TShark disponivel no PATH tem prioridade sobre os caminhos de instalacao predefinidos."""
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    monkeypatch.setattr(parser.shutil, "which", lambda _: "/usr/local/bin/tshark")
    assert parser.find_tshark_binary() == "/usr/local/bin/tshark"


@pytest.mark.parametrize(("platform", "environment", "installed"), [
    ("nt", {}, "C:/Program Files/Wireshark/tshark.exe"),
    ("nt", {}, "C:/Program Files (x86)/Wireshark/tshark.exe"),
    ("nt", {"ProgramFiles": "D:/Applications"}, "D:/Applications/Wireshark/tshark.exe"),
    ("nt", {"ProgramFiles(x86)": "D:/Apps32"}, "D:/Apps32/Wireshark/tshark.exe"),
    ("posix", {}, "/Applications/Wireshark.app/Contents/MacOS/tshark"),
])
def test_standard_installation_discovery(monkeypatch, platform, environment, installed):
    # Replace only the parser's os reference; changing real os.name would affect pytest.
    """Verifica a descoberta do TShark nos caminhos de instalacao habituais de Windows e macOS."""
    monkeypatch.setattr(parser, "os", SimpleNamespace(name=platform, environ=environment))
    monkeypatch.setattr(parser.shutil, "which", lambda _: None)
    monkeypatch.setattr(parser.Path, "is_file", lambda candidate: candidate == Path(installed))
    assert parser.find_tshark_binary() == str(Path(installed))


@pytest.mark.parametrize("platform", ["nt", "posix"])
def test_missing_tshark_explains_installation_and_override(monkeypatch, platform):
    """Verifica que a ausencia do TShark produz instrucoes sobre instalacao e configuracao de TSHARK_PATH."""
    monkeypatch.setattr(parser, "os", SimpleNamespace(name=platform, environ={}))
    monkeypatch.setattr(parser.shutil, "which", lambda _: None)
    monkeypatch.setattr(parser.Path, "is_file", lambda _: False)
    with pytest.raises(parser.PcapParserError, match="Wireshark/TShark.*TSHARK_PATH"):
        parser.find_tshark_binary()


@pytest.mark.parametrize("use_directory", [False, True])
def test_invalid_input_never_starts_a_process(tmp_path, runner, use_directory):
    """Impede iniciar o TShark quando a entrada nao existe ou e um diretorio."""
    target = tmp_path if use_directory else tmp_path / "missing.pcap"
    with pytest.raises(parser.PcapParserError, match="não encontrado"):
        parser._run_tshark_json(str(target), "tls", ["frame.number"])
    runner.assert_not_called()


def test_process_uses_literal_arguments_and_offline_name_resolution(capture, runner):
    """Verifica argumentos literais, leitura offline, campos pedidos e opcoes de execucao do subprocesso."""
    decoded = [{"_source": {"layers": {"frame.number": ["1"]}}}]
    runner.return_value.stdout = json.dumps(decoded)
    result = parser._run_tshark_json(str(capture), "tls.handshake.type == 2", ["frame.number", "ip.src"])
    assert result == decoded
    command = runner.call_args.args[0]
    assert command[0] == "path with spaces/tshark"
    assert command[command.index("-r") + 1] == str(capture)
    assert command[command.index("-Y") + 1] == "tls.handshake.type == 2"
    assert command[command.index("-T") + 1] == "json"
    assert command[-4:] == ["-e", "frame.number", "-e", "ip.src"]
    assert "-n" in command and "-2" in command
    assert "-i" not in command and "-w" not in command
    options = runner.call_args.kwargs
    assert options.get("shell", False) is False
    assert options["check"] is True and options["capture_output"] is True
    assert options["timeout"] == 120
    assert options["encoding"] == "utf-8" and options["errors"] == "replace"


@pytest.mark.parametrize("stdout", ["", " \n\t", "[]", "\n[]\n"])
def test_no_matching_packets_is_a_valid_empty_result(capture, runner, stdout):
    """Aceita saida vazia ou uma lista JSON vazia como ausencia de pacotes correspondentes."""
    runner.return_value.stdout = stdout
    assert parser._run_tshark_json(str(capture), "tls", []) == []


def test_successful_process_warning_is_preserved(capture, runner, caplog):
    """Verifica que avisos do TShark sao registados mesmo quando a execucao termina com sucesso."""
    runner.return_value.stderr = "  capture warning  \n"
    with caplog.at_level(logging.WARNING, logger=parser.__name__):
        assert parser._run_tshark_json(str(capture), "tls", []) == []
    assert "capture warning" in caplog.text


@pytest.mark.parametrize("stdout", ["{", "not JSON", "[] trailing data"])
def test_invalid_json_raises_a_parser_error_with_cause(capture, runner, stdout):
    """Exige um erro do parser com a causa original quando o TShark devolve JSON invalido."""
    runner.return_value.stdout = stdout
    with pytest.raises(parser.PcapParserError, match="interpretar") as caught:
        parser._run_tshark_json(str(capture), "tls", [])
    assert isinstance(caught.value.__cause__, json.JSONDecodeError)


@pytest.mark.parametrize("stdout", ["null", "{}", "42", '"text"', '[null]', '[1]', '[{}, "bad"]'])
def test_valid_json_with_invalid_packet_shape_is_rejected(capture, runner, stdout):
    """Rejeita JSON valido cuja estrutura nao seja uma lista de dicionarios de pacotes."""
    runner.return_value.stdout = stdout
    with pytest.raises(parser.PcapParserError, match="lista de pacotes"):
        parser._run_tshark_json(str(capture), "tls", [])


@pytest.mark.parametrize(("error", "message"), [
    (FileNotFoundError("removed binary"), "executar o tshark"),
    (PermissionError("permission denied"), "executar o tshark"),
    (subprocess.TimeoutExpired("tshark", 120), "120 segundos"),
    (subprocess.CalledProcessError(2, "tshark", stderr="corrupt capture"), "corrupt capture"),
    (subprocess.CalledProcessError(2, "tshark", stderr=None), "exit status 2"),
    (subprocess.CalledProcessError(2, "tshark", stderr=""), "exit status 2"),
])
def test_process_errors_keep_actionable_details_and_cause(capture, runner, error, message):
    """Preserva a causa e os detalhes uteis dos erros de execucao, permissoes, timeout e retorno do TShark."""
    runner.side_effect = error
    with pytest.raises(parser.PcapParserError, match=message) as caught:
        parser._run_tshark_json(str(capture), "tls", [])
    assert caught.value.__cause__ is error


@pytest.mark.parametrize(("raw", "expected"), [
    (None, None), ("", None), ("bad", None), ("0xZZ", None),
    ("0", 0), (0, 0), ("001", 1), (" 0X0304 ", 772), ("771", 771),
])
def test_numeric_wire_values(raw, expected):
    """Verifica a interpretacao de valores numericos decimais e hexadecimais, incluindo entradas invalidas."""
    assert parser._number(raw) == expected


@pytest.mark.parametrize(("raw", "expected"), [
    ("0x0300", "SSL 3.0"), ("768", "SSL 3.0"),
    ("0x0301", "TLS 1.0"), ("769", "TLS 1.0"),
    ("0x0302", "TLS 1.1"), ("770", "TLS 1.1"),
    ("0x0303", "TLS 1.2"), ("771", "TLS 1.2"),
    ("0x0304", "TLS 1.3"), ("772", "TLS 1.3"),
    ("0X0304", "TLS 1.3"), ("custom", "custom"), ("0x7f17", "0x7f17"),
    (None, None), ("", None),
])
def test_version_normalization_does_not_invent_unknown_versions(raw, expected):
    """Normaliza versoes TLS conhecidas e preserva valores desconhecidos sem inventar uma versao."""
    assert parser._normalize_tls_version(raw) == expected


@pytest.mark.parametrize(("value", "expected"), [
    (None, []), ([], []), ("", []), ("one", ["one"]),
    (0, ["0"]), ([None, "", "a", 22], ["a", "22"]),
])
def test_fields_allow_tshark_scalar_and_list_representations(value, expected):
    """Aceita campos TShark escalares ou em lista, removendo entradas vazias e convertendo valores para texto."""
    assert parser._get_field_list({"field": value}, "field") == expected
    assert parser._get_field_list({}, "absent") == []


def test_first_field_falls_back_from_empty_ipv4_to_ipv6():
    """Usa IPv6 quando IPv4 esta vazio e devolve o valor predefinido quando nao existe nenhum campo."""
    layers = {"ip.src": [None, ""], "ipv6.src": ["2001:db8::1", "2001:db8::2"]}
    assert parser._get_field_first(layers, ["absent", "ip.src", "ipv6.src"]) == "2001:db8::1"
    assert parser._get_field_first({}, ["ip.src"], "unknown") == "unknown"


def test_orchestrator_preserves_all_three_results_and_source_path(monkeypatch):
    """Verifica que a funcao principal preserva resultados TLS, SSH e cleartext e o caminho da captura."""
    expected = {}
    for name, key in [("extract_tls_metadata", "tls_sessions"),
                      ("extract_ssh_metadata", "ssh_sessions"),
                      ("detect_cleartext_traffic", "cleartext_traffic")]:
        expected[key] = [{"packet_number": len(expected) + 1}]
        monkeypatch.setattr(parser, name, Mock(return_value=expected[key]))
    path = Path("capture.pcapng")
    assert parser.parse_network_pcap(path) == {"pcap_file": str(path), **expected}
    for method in [parser.extract_tls_metadata, parser.extract_ssh_metadata, parser.detect_cleartext_traffic]:
        method.assert_called_once_with(path)


def test_orchestrator_does_not_hide_a_partial_failure(monkeypatch):
    """Propaga uma falha parcial da extracao e impede continuar como se o processamento tivesse sido bem-sucedido."""
    monkeypatch.setattr(parser, "extract_tls_metadata", Mock(return_value=[]))
    monkeypatch.setattr(parser, "extract_ssh_metadata", Mock(side_effect=parser.PcapParserError("SSH decode failed")))
    cleartext = Mock(return_value=[])
    monkeypatch.setattr(parser, "detect_cleartext_traffic", cleartext)
    with pytest.raises(parser.PcapParserError, match="SSH decode failed"):
        parser.parse_network_pcap("capture.pcap")
    cleartext.assert_not_called()

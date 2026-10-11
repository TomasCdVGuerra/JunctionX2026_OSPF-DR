"""Setup rejects incompatible environments and propagates runtime failures."""
from pathlib import Path
import subprocess
import sys

import pytest

import run
from scripts import check_environment


def test_incompatible_environment_is_preserved(tmp_path, monkeypatch):
    python = tmp_path / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    python.parent.mkdir(parents=True)
    python.write_bytes(b"existing environment")
    monkeypatch.setattr(run, "_version", lambda command: "3.14")
    with pytest.raises(run.SetupError, match="Rename the old"):
        run._ensure_environment(tmp_path)
    assert python.read_bytes() == b"existing environment"


def test_partial_environment_is_not_overwritten(tmp_path):
    folder = tmp_path / ".venv"
    folder.mkdir()
    marker = folder / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(run.SetupError, match="no usable Python"):
        run._ensure_environment(tmp_path)
    assert marker.read_text(encoding="utf-8") == "keep"


def test_dependency_check_detects_changed_pin(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("pytest==0.0.0\n", encoding="utf-8")
    assert not run._dependencies_match(Path(sys.executable), requirements)


def test_setup_fails_if_required_tshark_is_unavailable(monkeypatch):
    from scanner.network_scanner.parser import tshark_parser

    def unavailable():
        raise tshark_parser.PcapParserError("TShark unavailable")
    monkeypatch.setattr(tshark_parser, "find_tshark_binary", unavailable)
    assert check_environment.main([]) == 0
    assert check_environment.main(["--require-tshark"]) == 1


def test_runtime_failure_stops_setup_before_launch(monkeypatch, capsys):
    monkeypatch.setattr(run, "_ensure_environment", lambda root: Path(sys.executable))
    monkeypatch.setattr(run, "_dependencies_match", lambda *args: True)
    commands = []
    def execute(command):
        commands.append(command)
        if any("check_environment.py" in arg for arg in command):
            raise run.SetupError("Runtime verification failed")
    monkeypatch.setattr(run, "_run", execute)
    assert run.main([]) == 1
    assert not any("streamlit" in command for command in commands)
    assert "Runtime verification failed" in capsys.readouterr().err


def test_help_works_from_outside_repository_without_dependencies(tmp_path):
    result = subprocess.run([sys.executable, str(run.ROOT / "run.py"), "--help"],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0 and "--require-tshark" in result.stdout

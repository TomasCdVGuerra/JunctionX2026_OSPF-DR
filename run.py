"""Single-command setup and launch; requires only the Python standard library."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
EXPECTED_PYTHON = "3.13"


class SetupError(RuntimeError):
    """A setup step failed; the existing environment is preserved."""


def _version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            [*command, "-c", "import sys; print('%s.%s' % sys.version_info[:2])"],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _find_python() -> list[str]:
    candidates = [[sys.executable]]
    launcher = shutil.which("py")
    if launcher:
        candidates.append([launcher, "-3.13"])
    for name in ("python3.13", "python3", "python"):
        executable = shutil.which(name)
        if executable:
            candidates.append([executable])
    for command in candidates:
        if _version(command) == EXPECTED_PYTHON:
            return command
    raise SetupError(
        "Python 3.13 was not found. Install Python 3.13 from https://www.python.org/downloads/ "
        "and retry with 'py -3.13 run.py' (Windows) or 'python3.13 run.py' (Linux/macOS)."
    )


def _run(command: list[str]) -> None:
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode:
        raise SetupError(f"Command failed (exit {result.returncode}): {' '.join(command)}")


def _ensure_environment(root: Path) -> Path:
    folder = root / ".venv"
    python = folder / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file():
        if folder.exists():
            raise SetupError(".venv exists but has no usable Python. Rename it and retry; it was not overwritten.")
        _run([*_find_python(), "-m", "venv", str(folder)])
    if _version([str(python)]) != EXPECTED_PYTHON:
        raise SetupError(".venv must use Python 3.13. Rename the old .venv and retry; it was not overwritten.")
    return python


def _dependencies_match(python: Path, requirements: Path) -> bool:
    # Check distributions in the project environment, never the system Python.
    check = """
import sys
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
for line in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    if line.count('==') != 1:
        sys.exit(1)
    name, expected = line.split('==')
    try:
        if version(name) != expected:
            sys.exit(1)
    except PackageNotFoundError:
        sys.exit(1)
"""
    result = subprocess.run([str(python), "-c", check, str(requirements)], cwd=ROOT)
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare QuantumTrace and launch its dashboard.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--setup", action="store_true", help="prepare and verify the environment only")
    modes.add_argument("--test", action="store_true", help="prepare the environment and run the complete suite")
    modes.add_argument("--ui", action="store_true", help="launch the dashboard (default)")
    parser.add_argument("--require-tshark", action="store_true", help="fail setup if real PCAP scanning is unavailable")
    parser.add_argument("--port", type=int, default=8501, help="dashboard port (default: 8501)")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        print("[1/4] Preparing the Python 3.13 project environment...", flush=True)
        python = _ensure_environment(ROOT)
        print(f"[2/4] Checking pinned dependencies in {python.parent.parent}...", flush=True)
        requirements = ROOT / "requirements.txt"
        if not _dependencies_match(python, requirements):
            _run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(requirements)])
        else:
            print("Pinned dependencies already installed; no download needed.", flush=True)
        print("[3/4] Checking dependency consistency and runtime...", flush=True)
        _run([str(python), "-m", "pip", "check"])
        check = [str(python), str(ROOT / "scripts/check_environment.py")]
        if args.require_tshark:
            check.append("--require-tshark")
        _run(check)
        if args.setup:
            print("[4/4] Setup complete. Run the same command without --setup to open the dashboard.", flush=True)
        elif args.test:
            print("[4/4] Running the complete test suite...", flush=True)
            _run([str(python), "-m", "pytest", "-q", "--tb=short"])
        else:
            print(f"[4/4] Starting the dashboard at http://localhost:{args.port} (Ctrl+C to stop)...", flush=True)
            _run([str(python), "-m", "streamlit", "run", str(ROOT / "dashboard.py"), "--server.port", str(args.port)])
        return 0
    except (SetupError, OSError) as exc:
        print(f"Setup stopped: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

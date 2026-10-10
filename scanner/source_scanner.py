"""Thin dispatcher and orchestrator for multi-language source code scanning."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scanner.models import CryptoFinding

logger = logging.getLogger(__name__)

__all__ = [
    "scan_file",
    "scan_source_directory",
]


def scan_file(
    file_path: str | Path,
    rules: list[Any] | None = None,
    base_dir: str | Path | None = None,
) -> list[CryptoFinding]:
    """Detect language by file extension and dispatch to the appropriate language scanner."""
    file_path = Path(file_path)
    if not file_path.is_file():
        return []

    suffix = file_path.suffix.lower()

    if suffix == ".go":
        from scanner.go_scanner import scan_go_file
        effective_base = Path(base_dir) if base_dir is not None else None
        return scan_go_file(file_path, base_dir=effective_base, rules=rules)

    if suffix == ".py":
        try:
            import scanner.python_scanner as py_mod
            if hasattr(py_mod, "scan_python_file"):
                return py_mod.scan_python_file(file_path, base_dir=base_dir)
            logger.warning("Python scanner unavailable; file was not analyzed: %s", file_path)
        except Exception as exc:
            logger.warning("Python scanner failed on %s: %s", file_path, exc)
        return []

    if suffix == ".java":
        try:
            import scanner.java_scanner as java_mod
            if hasattr(java_mod, "scan_java_file"):
                return java_mod.scan_java_file(file_path, base_dir=base_dir)
            logger.warning("Java scanner unavailable; file was not analyzed: %s", file_path)
        except Exception as exc:
            logger.warning("Java scanner failed on %s: %s", file_path, exc)
        return []

    return []


def scan_source_directory(
    directory_path: str | Path,
    base_dir: str | Path | None = None,
) -> list[CryptoFinding]:
    """Recursively discover and dispatch source code files to language-specific scanners."""
    directory_path = Path(directory_path)
    if not directory_path.is_dir():
        return []

    effective_base = Path(base_dir) if base_dir is not None else directory_path
    findings: list[CryptoFinding] = []

    for path in sorted(directory_path.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".go", ".py", ".java"}:
            findings.extend(scan_file(path, base_dir=effective_base))

    return findings

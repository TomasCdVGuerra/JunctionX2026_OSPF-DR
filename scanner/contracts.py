"""Shared scanner protocol to support parallel implementation."""
from pathlib import Path
from typing import Protocol

from scanner.models import CryptoFinding


class Scanner(Protocol):
    def scan(self, path: Path) -> list[CryptoFinding]: ...

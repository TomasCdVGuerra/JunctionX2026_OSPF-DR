"""Shared utility functions and pattern rule contracts for QuantumTrace scanners."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from scanner.models import AssetType, QuantumRiskLevel


@dataclass
class SourcePatternRule:
    rule_id: str
    pattern: re.Pattern
    algorithm_name: str
    default_key_size: str | None
    risk_reasoning: str
    nist_standard: str
    risk_level: QuantumRiskLevel
    asset_type: AssetType

    def __post_init__(self) -> None:
        if isinstance(self.pattern, str):
            self.pattern = re.compile(self.pattern)


def _clean_constant_value(raw: str) -> str:
    """Strip quotes, byte slice syntax, type casts, and trailing symbols."""
    val = raw.strip()
    val = re.sub(r"//.*$", "", val).strip()
    val = re.sub(r"#.*$", "", val).strip()
    val = val.rstrip(";,")

    # Go byte slice: []byte("...") or []byte('...') or []byte(`...`)
    byte_slice = re.match(r"^\[\]byte\s*\(\s*(['\"`].*?['\"`])\s*\)$", val)
    if byte_slice:
        inner = byte_slice.group(1)
        return inner.strip("'\"`")

    # Python byte literal or string: b"..." / "..." / '...' / `...`
    if (val.startswith('b"') and val.endswith('"')) or (val.startswith("b'") and val.endswith("'")):
        return val[2:-1]
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")) or (val.startswith('`') and val.endswith('`')):
        return val[1:-1]

    # Numeric with underscores: 600_000 -> 600000
    if re.match(r"^\d[\d_]*$", val):
        return val.replace("_", "")

    return val if val else "unknown"


def resolve_constant(file_content: str, variable_name: str) -> str:
    """Search same-file declarations (Go const, Python uppercase assignments, Java static final)."""
    if not file_content or not variable_name:
        return "unknown"

    escaped_var = re.escape(variable_name)

    # 1. Go const block: const (\n ... var = val ... \n)
    block_matches = re.finditer(r"\bconst\s*\(([^)]+)\)", file_content, re.DOTALL)
    for block in block_matches:
        block_text = block.group(1)
        m = re.search(
            rf"^\s*{escaped_var}\b\s*(?:[a-zA-Z0-9_\[\]*]+)?\s*=\s*(.+?)(?://.*)?$",
            block_text,
            re.MULTILINE,
        )
        if m:
            val = _clean_constant_value(m.group(1))
            if val != "unknown":
                return val

    # 2. Go single const or var: const/var keyLen = 32 or var exportKey = []byte("...")
    go_single = re.search(
        rf"^\s*(?:const|var)\s+{escaped_var}\b\s*(?:[a-zA-Z0-9_\[\]*]+)?\s*=\s*(.+?)(?://.*)?$",
        file_content,
        re.MULTILINE,
    )
    if go_single:
        val = _clean_constant_value(go_single.group(1))
        if val != "unknown":
            return val

    # 3. Java static final: [public|private|protected] static final [type] KEY_SIZE = 2048;
    java_match = re.search(
        rf"\bstatic\s+final\s+[\w\[\]<>]+\s+{escaped_var}\b\s*=\s*(.+?)\s*;",
        file_content,
    )
    if java_match:
        val = _clean_constant_value(java_match.group(1))
        if val != "unknown":
            return val

    # 4. Python uppercase or standard assignment: KEY_LEN = 32
    py_match = re.search(
        rf"^\s*{escaped_var}\b\s*(?::\s*[^=]+)?\s*=\s*(.+?)(?:#.*)?$",
        file_content,
        re.MULTILINE,
    )
    if py_match:
        val = _clean_constant_value(py_match.group(1))
        if val != "unknown":
            return val

    return "unknown"


def infer_key_size_from_literal(literal_value: str) -> str:
    """Infer bit length from byte slice, hex string, numeric byte count, or string literal."""
    if not literal_value or literal_value == "unknown":
        return "unknown"

    cleaned = _clean_constant_value(literal_value)

    # 1. Numeric byte count (16 bytes -> 128 bits, 24 bytes -> 192, 32 bytes -> 256)
    if cleaned.isdigit():
        num = int(cleaned)
        if num in (16, 24, 32):
            return str(num * 8)
        if num in (128, 192, 256, 512, 1024, 2048, 3072, 4096):
            return str(num)

    # 2. Hex string (32 hex characters = 16 bytes = 128 bits, 64 hex characters = 32 bytes = 256 bits)
    if len(cleaned) in (32, 48, 64) and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        byte_len = len(cleaned) // 2
        return str(byte_len * 8)

    # 3. Known key material string literal length: 16 chars -> 128 bits, 24 chars -> 192 bits, 32 chars -> 256 bits
    if len(cleaned) in (16, 24, 32):
        return str(len(cleaned) * 8)

    return "unknown"

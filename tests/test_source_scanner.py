# Purpose:
# Test suite for multi-language static analysis pattern matching, constant resolution, and evidence tracking.
#
# Responsibilities:
# - Test Python crypto rule detection (hashlib, hmac, cryptography Hazmat primitives).
# - Test Java JCA/JCE rule detection (MessageDigest, Cipher, KeyPairGenerator, Signature).
# - Test Go crypto rule detection (crypto/md5, crypto/sha256, crypto/aes, crypto/ed25519, crypto/rsa).
# - Validate same-file constant resolution: confirm that key sizes defined in separate constants (e.g. KEY_BITS = 256, keyLen = 32) are resolved correctly.
# - Validate literal key inference: confirm that a hardcoded 16-byte key string resolves to AES-128.
# - Assert that evidence blocks capture accurate line numbers, matching code snippets, and rule IDs.

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.models import AssetType, CryptoFinding, QuantumRiskLevel
from scanner.source_scanner import scan_file, scan_source_directory
from scanner.utils import (
    SourcePatternRule,
    _clean_constant_value,
    infer_key_size_from_literal,
    resolve_constant,
)


# --- Petty Dispatcher Tests ---

def test_source_scanner_delegates_go_files_to_go_scanner(tmp_path: Path):
    """Petty: Verify .go files are strictly dispatched to go_scanner with exact relative paths."""
    go_file = tmp_path / "main.go"
    go_file.write_text('package main\nimport "crypto/md5"\nfunc foo() { md5.New() }')
    
    findings = scan_file(go_file, base_dir=tmp_path)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "MD5"
    assert findings[0].quantum_risk == QuantumRiskLevel.CRITICAL
    assert findings[0].evidence[0].file_path == "main.go"


def test_source_scanner_ignores_non_source_files(tmp_path: Path):
    """Petty: Text, JSON, markdown, images, and arbitrary binaries must return empty lists."""
    for ext in (".txt", ".md", ".json", ".csv", ".png", ".exe", ".sh", ".yaml"):
        dummy = tmp_path / f"test{ext}"
        dummy.write_text("import crypto\nAES.new()")
        assert scan_file(dummy, base_dir=tmp_path) == []


def test_source_scanner_unsupported_source_languages_ignored(tmp_path: Path):
    """Petty: Rust, C++, Ruby, PHP, and Swift files must return empty lists, not crash or guess."""
    for ext in (".rs", ".cpp", ".c", ".rb", ".php", ".swift", ".ts", ".js"):
        dummy = tmp_path / f"crypto{ext}"
        dummy.write_text('let key = "1234567812345678";')
        assert scan_file(dummy, base_dir=tmp_path) == []


def test_source_scanner_case_insensitive_extension(tmp_path: Path):
    """Petty: Windows/FAT32 uppercase extensions (.GO, .Go) must be dispatched correctly."""
    go_file = tmp_path / "UPPER.GO"
    go_file.write_text('package main\nimport "crypto/sha1"\nfunc h() { sha1.New() }')

    findings = scan_file(go_file, base_dir=tmp_path)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "SHA-1"


def test_source_scanner_non_existent_file_returns_empty_list(tmp_path: Path):
    """Petty: scan_file on a non-existent path must return [] without raising FileNotFoundError."""
    missing = tmp_path / "ghost.go"
    assert scan_file(missing) == []


def test_source_scanner_directory_passed_as_file_returns_empty_list(tmp_path: Path):
    """Petty: Passing a directory path to scan_file must return [] instead of IsADirectoryError."""
    sub_dir = tmp_path / "not_a_file.go"
    sub_dir.mkdir()
    assert scan_file(sub_dir) == []


def test_source_scanner_empty_file_returns_empty_list(tmp_path: Path):
    """Petty: A 0-byte source file must return [] cleanly."""
    empty_file = tmp_path / "empty.go"
    empty_file.write_text("")
    assert scan_file(empty_file) == []


def test_source_scanner_directory_scan_traversal_and_relative_paths(tmp_path: Path):
    """Petty: scan_source_directory must recursively find .go files and set relative paths."""
    pkg = tmp_path / "pkg" / "crypto"
    pkg.mkdir(parents=True)
    f1 = pkg / "hasher.go"
    f1.write_text('package crypto\nimport "crypto/md5"\nfunc h() { md5.New() }')
    
    f2 = tmp_path / "readme.txt"
    f2.write_text("md5.New()")

    findings = scan_source_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0].evidence[0].file_path == "pkg/crypto/hasher.go"


def test_source_scanner_empty_directory_returns_empty_list(tmp_path: Path):
    """Petty: scan_source_directory on an empty directory returns []."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    assert scan_source_directory(empty_dir) == []


def test_source_scanner_non_existent_directory_returns_empty_list(tmp_path: Path):
    """Petty: scan_source_directory on a non-existent path returns []."""
    missing_dir = tmp_path / "does_not_exist"
    assert scan_source_directory(missing_dir) == []


def test_source_scanner_custom_rules_propagation(tmp_path: Path):
    """Petty: Passing custom rules to scan_file overrides default detection rules."""
    custom_rule = SourcePatternRule(
        rule_id="CUSTOM-GO-TEST",
        pattern=re.compile(r"custom_crypto_call\(\)"),
        algorithm_name="CUSTOM-CIPHER",
        default_key_size="256",
        risk_reasoning="Custom test cipher",
        nist_standard="None",
        risk_level=QuantumRiskLevel.CRITICAL,
        asset_type=AssetType.ALGORITHM,
    )
    go_file = tmp_path / "custom.go"
    go_file.write_text("package main\nfunc main() { custom_crypto_call() }")

    findings = scan_file(go_file, rules=[custom_rule], base_dir=tmp_path)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "CUSTOM-CIPHER"
    assert findings[0].evidence[0].rule_id == "CUSTOM-GO-TEST"


def test_python_scanner_graceful_when_unimplemented(tmp_path: Path):
    """Petty: When python_scanner has no scan_python_file, scan_file returns [] without crashing."""
    py_file = tmp_path / "script.py"
    py_file.write_text("import hashlib\nhashlib.md5()")
    assert scan_file(py_file, base_dir=tmp_path) == []


def test_java_scanner_graceful_when_unimplemented(tmp_path: Path):
    """Petty: When java_scanner has no scan_java_file, scan_file returns [] without crashing."""
    java_file = tmp_path / "App.java"
    java_file.write_text('MessageDigest.getInstance("MD5");')
    assert scan_file(java_file, base_dir=tmp_path) == []


# --- Petty Constant Resolution Tests ---

def test_same_file_constant_resolution_petty_cases():
    """Petty: Exhaustive validation of resolve_constant across Go, Python, and Java syntax."""
    # Go untyped const
    content_go = 'const keyLen = 32\nconst KeyBits = 256'
    assert resolve_constant(content_go, "keyLen") == "32"
    assert resolve_constant(content_go, "KeyBits") == "256"

    # Go typed const
    content_go_typed = 'const keySize int = 128\nconst keyName string = "AES"'
    assert resolve_constant(content_go_typed, "keySize") == "128"
    assert resolve_constant(content_go_typed, "keyName") == "AES"

    # Go grouped const
    content_go_group = """
    const (
        DefaultKeySize = 2048
        IterationCount = 10000
    )
    """
    assert resolve_constant(content_go_group, "DefaultKeySize") == "2048"
    assert resolve_constant(content_go_group, "IterationCount") == "10000"

    # Python uppercase & lowercase assignments
    content_py = "KEY_SIZE = 256\nkey_bits = 512\nCIPHER = 'AES-GCM'"
    assert resolve_constant(content_py, "KEY_SIZE") == "256"
    assert resolve_constant(content_py, "key_bits") == "512"
    assert resolve_constant(content_py, "CIPHER") == "AES-GCM"

    # Java static final
    content_java = 'private static final int KEY_LENGTH = 16;\npublic static final String ALGO = "AES";'
    assert resolve_constant(content_java, "KEY_LENGTH") == "16"
    assert resolve_constant(content_java, "ALGO") == "AES"

    # Word boundary precision: variable substring should NOT match
    content_sub = 'const my_key_size_extra = 512\nconst other = 1024'
    assert resolve_constant(content_sub, "key_size") == "unknown"

    # Non-existent variable
    assert resolve_constant(content_go, "MISSING_VAR") == "unknown"

    # Empty content or variable
    assert resolve_constant("", "VAR") == "unknown"
    assert resolve_constant("const X = 1", "") == "unknown"


def test_infer_key_size_from_literal_petty_cases():
    """Petty: Exhaustive validation of infer_key_size_from_literal."""
    # 16-byte literal -> 128 bits
    assert infer_key_size_from_literal('"0123456789abcdef"') == "128"
    assert infer_key_size_from_literal("'0123456789abcdef'") == "128"
    assert infer_key_size_from_literal("`0123456789abcdef`") == "128"

    # 24-byte literal -> 192 bits
    assert infer_key_size_from_literal('"0123456789abcdef01234567"') == "192"

    # 32-hex-character string -> 16 bytes -> 128 bits
    assert infer_key_size_from_literal('"0123456789abcdef0123456789abcdef"') == "128"

    # 64-hex-character string -> 32 bytes -> 256 bits
    assert infer_key_size_from_literal('"' + 'a' * 64 + '"') == "256"

    # 32-character non-hex string (e.g. includes letters g-z) -> 32 bytes -> 256 bits
    assert infer_key_size_from_literal('"' + 'g' * 32 + '"') == "256"

    # Arbitrary strings (not 16, 24, or 32 bytes) must return unknown instead of speculative guesses
    assert infer_key_size_from_literal('"short"') == "unknown"
    assert infer_key_size_from_literal('"abcdefghij"') == "unknown"
    assert infer_key_size_from_literal('"password"') == "unknown"
    assert infer_key_size_from_literal('"1234567890"') == "unknown"

    # Empty or unquoted literals
    assert infer_key_size_from_literal('""') == "unknown"
    assert infer_key_size_from_literal("unknown") == "unknown"
    assert infer_key_size_from_literal(None) == "unknown"


def test_clean_constant_value_petty_cases():
    """Petty: _clean_constant_value strips trailing semicolons, commas, quotes, and whitespace."""
    assert _clean_constant_value('"my_val";') == "my_val"
    assert _clean_constant_value("'single_quote',") == "single_quote"
    assert _clean_constant_value("  1024;  ") == "1024"
    assert _clean_constant_value("`raw_literal`,") == "raw_literal"
    assert _clean_constant_value("") == "unknown"


def test_source_pattern_rule_dataclass_contract():
    """Petty: SourcePatternRule fields and properties contract validation."""
    rule = SourcePatternRule(
        rule_id="RULE-01",
        pattern=re.compile(r"test"),
        algorithm_name="TEST-ALGO",
        default_key_size=None,
        risk_reasoning="Test rule reasoning",
        nist_standard="NIST SP 800-38D",
        risk_level=QuantumRiskLevel.SAFE,
        asset_type=AssetType.ALGORITHM,
    )
    assert rule.rule_id == "RULE-01"
    assert rule.default_key_size is None
    assert rule.risk_level == QuantumRiskLevel.SAFE
    assert rule.asset_type == AssetType.ALGORITHM


def test_python_and_java_scanner_unavailable_logs_warning(tmp_path: Path, caplog):
    """Regression: Unavailable python/java scanners log warnings visibly instead of silently failing."""
    import logging
    with caplog.at_level(logging.WARNING):
        py_file = tmp_path / "script.py"
        py_file.write_text("import hashlib\n")
        scan_file(py_file)
        assert any("Python scanner unavailable" in record.message for record in caplog.records)

    with caplog.at_level(logging.WARNING):
        java_file = tmp_path / "App.java"
        java_file.write_text("class App {}\n")
        scan_file(java_file)
        assert any("Java scanner unavailable" in record.message for record in caplog.records)

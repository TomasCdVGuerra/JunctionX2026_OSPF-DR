"""Unit and integration tests for scanner/go_scanner.py and scanner/source_scanner.py."""

from pathlib import Path
import pytest

from scanner.models import AssetType, CryptoFinding, CryptoFunction, QuantumRiskLevel
from scanner.utils import (
    SourcePatternRule,
    infer_key_size_from_literal,
    resolve_constant,
)
from scanner.source_scanner import (
    scan_file,
    scan_source_directory,
)
from scanner.go_scanner import (
    GO_RULES,
    detect_custom_kdf,
    resolve_go_constant,
    scan,
    scan_go_file,
)

SAMPLE_GO_DIR = Path("support-materials/sample-repos/go")


# --- 1. Tests for the 8 Sample Repositories ---

def test_agent_enrollment_ed25519():
    """Verify agent-enrollment extracts Ed25519 as Critical with 256-bit key size."""
    file_path = SAMPLE_GO_DIR / "agent-enrollment" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) >= 1
    ed_findings = [f for f in findings if "Ed25519" in f.algorithm_name]
    assert len(ed_findings) > 0
    for finding in ed_findings:
        assert finding.quantum_risk == QuantumRiskLevel.CRITICAL
        assert finding.key_size == 256
        assert finding.source_type == "source-code"
        assert finding.evidence[0].line_number >= 1
        assert finding.evidence[0].rule_id.startswith("go-ed25519")


def test_auth_gateway_pbkdf2_and_hmac_safe():
    """Verify auth-gateway custom PBKDF2 over HMAC-SHA256 is Safe and never Critical."""
    file_path = SAMPLE_GO_DIR / "auth-gateway" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) >= 2
    pbkdf2_findings = [f for f in findings if "PBKDF2" in f.algorithm_name]
    hmac_findings = [f for f in findings if f.algorithm_name == "HMAC-SHA256"]

    assert len(pbkdf2_findings) == 1
    assert pbkdf2_findings[0].quantum_risk == QuantumRiskLevel.SAFE
    assert pbkdf2_findings[0].crypto_function == CryptoFunction.KDF
    assert pbkdf2_findings[0].evidence[0].rule_id == "go-custom-pbkdf2"

    assert len(hmac_findings) >= 1
    for hmac_f in hmac_findings:
        assert hmac_f.quantum_risk == QuantumRiskLevel.SAFE
        assert hmac_f.crypto_function == CryptoFunction.MAC

    # Ensure NO findings in auth-gateway are Critical
    for f in findings:
        assert f.quantum_risk != QuantumRiskLevel.CRITICAL, f"Unexpected Critical finding: {f.algorithm_name}"


def test_batch_pipeline_aes_128_ecb():
    """Verify batch-pipeline resolves exportKey to 128-bit AES-ECB mode (Critical due to lack of semantic security)."""
    file_path = SAMPLE_GO_DIR / "batch-pipeline" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) == 1
    aes_finding = findings[0]
    assert "AES-128" in aes_finding.algorithm_name
    assert aes_finding.key_size == 128
    assert aes_finding.mode == "ECB"
    assert aes_finding.quantum_risk == QuantumRiskLevel.CRITICAL
    assert aes_finding.evidence[0].rule_id == "go-aes-128-ecb"


def test_config_sync_sha384_and_hmac():
    """Verify config-sync extracts SHA-384 and HMAC-SHA256 as Safe."""
    file_path = SAMPLE_GO_DIR / "config-sync" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) >= 2
    sha384_findings = [f for f in findings if f.algorithm_name == "SHA-384"]
    hmac_findings = [f for f in findings if "HMAC" in f.algorithm_name]

    assert len(sha384_findings) == 1
    assert sha384_findings[0].quantum_risk == QuantumRiskLevel.SAFE

    assert len(hmac_findings) == 1
    assert hmac_findings[0].quantum_risk == QuantumRiskLevel.SAFE


def test_invoice_service_rsa_1024_and_sha1():
    """Verify invoice-service extracts RSA-1024 (Critical) and SHA-1 (Critical)."""
    file_path = SAMPLE_GO_DIR / "invoice-service" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    rsa_keygen = [f for f in findings if f.algorithm_name == "RSA-1024"]
    assert len(rsa_keygen) == 1
    assert rsa_keygen[0].key_size == 1024
    assert rsa_keygen[0].quantum_risk == QuantumRiskLevel.CRITICAL
    assert rsa_keygen[0].crypto_function == CryptoFunction.KEYGEN

    sha1_findings = [f for f in findings if f.algorithm_name == "SHA-1"]
    assert len(sha1_findings) >= 1
    for sf in sha1_findings:
        assert sf.quantum_risk == QuantumRiskLevel.CRITICAL


def test_member_directory_md5():
    """Verify member-directory extracts MD5 as Critical (classically broken)."""
    file_path = SAMPLE_GO_DIR / "member-directory" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) == 1
    md5_finding = findings[0]
    assert md5_finding.algorithm_name == "MD5"
    assert md5_finding.quantum_risk == QuantumRiskLevel.CRITICAL
    assert md5_finding.classical_risk == QuantumRiskLevel.CRITICAL


def test_release_feed_sha1():
    """Verify release-feed extracts SHA-1 as Critical (classically broken)."""
    file_path = SAMPLE_GO_DIR / "release-feed" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) == 1
    sha1_finding = findings[0]
    assert sha1_finding.algorithm_name == "SHA-1"
    assert sha1_finding.quantum_risk == QuantumRiskLevel.CRITICAL


def test_telemetry_relay_aes_256_gcm():
    """Verify telemetry-relay resolves keyLen const=32 to AES-256-GCM (Safe)."""
    file_path = SAMPLE_GO_DIR / "telemetry-relay" / "main.go"
    findings = scan_go_file(file_path, base_dir=SAMPLE_GO_DIR)

    assert len(findings) >= 1
    for f in findings:
        assert "AES-256" in f.algorithm_name
        assert f.key_size == 256
        assert f.mode == "GCM"
        assert f.quantum_risk == QuantumRiskLevel.SAFE


# --- 2. Negative Cases & Invariants ---

def test_negative_cases_hmac_and_pbkdf2_never_critical():
    """Verify that HMAC-SHA256 and PBKDF2 are NEVER classified as Critical."""
    all_findings = scan_source_directory(SAMPLE_GO_DIR)
    for finding in all_findings:
        if "HMAC" in finding.algorithm_name or "PBKDF2" in finding.algorithm_name:
            assert finding.quantum_risk != QuantumRiskLevel.CRITICAL, (
                f"Finding {finding.algorithm_name} must not be Critical!"
            )


def test_comments_and_string_literals_ignored(tmp_path):
    """Verify that usages inside comments or string literals do not produce findings."""
    code = """package main
import "fmt"
// ed25519.GenerateKey(rand.Reader)
// rsa.GenerateKey(rand.Reader, 2048)
/*
md5.Sum(data)
sha1.Sum(data)
*/
func main() {
    msg := "ed25519.Sign should not be flagged in a string literal"
    fmt.Println(msg)
}
"""
    test_file = tmp_path / "commented.go"
    test_file.write_text(code, encoding="utf-8")

    findings = scan_go_file(test_file)
    assert len(findings) == 0


# --- 3. Constant Resolution & Literal Inference ---

def test_resolve_constant_go_block():
    content = """package main
const (
    iterations = 600_000
    saltLen    = 16
    keyLen     = 32
)
"""
    assert resolve_constant(content, "keyLen") == "32"
    assert resolve_constant(content, "saltLen") == "16"
    assert resolve_constant(content, "iterations") == "600000"
    assert resolve_constant(content, "nonexistent") == "unknown"


def test_resolve_constant_go_var_and_single():
    content = """package main
var exportKey = []byte("0123456789ABCDEF")
const maxRetries = 5
"""
    assert resolve_constant(content, "exportKey") == "0123456789ABCDEF"
    assert resolve_constant(content, "maxRetries") == "5"


def test_resolve_constant_python_and_java():
    py_code = """KEY_LEN = 32
AES_KEY = "0123456789ABCDEF"
"""
    assert resolve_constant(py_code, "KEY_LEN") == "32"
    assert resolve_constant(py_code, "AES_KEY") == "0123456789ABCDEF"

    java_code = """public class Crypto {
    private static final int KEY_SIZE = 2048;
    static final String CIPHER = "AES";
}
"""
    assert resolve_constant(java_code, "KEY_SIZE") == "2048"
    assert resolve_constant(java_code, "CIPHER") == "AES"


def test_infer_key_size_from_literal():
    assert infer_key_size_from_literal("0123456789ABCDEF") == "128"
    assert infer_key_size_from_literal('[]byte("0123456789ABCDEF")') == "128"
    assert infer_key_size_from_literal("shared-signing-key-32-bytes-long") == "256"
    assert infer_key_size_from_literal("16") == "128"
    assert infer_key_size_from_literal("32") == "256"
    assert infer_key_size_from_literal("1024") == "1024"
    assert infer_key_size_from_literal("2048") == "2048"
    assert infer_key_size_from_literal("unknown") == "unknown"
    assert infer_key_size_from_literal("") == "unknown"


# --- 4. Directory Scanning & Protocol Compliance ---

def test_scan_source_directory_returns_valid_models():
    """Verify scan_source_directory returns valid CryptoFinding instances with correct metadata."""
    findings = scan_source_directory(SAMPLE_GO_DIR)
    assert len(findings) > 0

    for finding in findings:
        assert isinstance(finding, CryptoFinding)
        assert finding.source_type == "source-code"
        assert finding.asset_type == AssetType.ALGORITHM
        assert len(finding.evidence) >= 1
        ev = finding.evidence[0]
        assert ev.line_number is not None and ev.line_number >= 1
        assert ev.rule_id != ""
        assert ev.file_path != ""
        # Evidence file path should be relative to base_dir
        assert not ev.file_path.startswith("/")


def test_scan_protocol_on_directory():
    """Verify scanner.go_scanner.scan() adheres to the Scanner Protocol."""
    findings = scan(SAMPLE_GO_DIR)
    assert len(findings) > 0
    assert all(isinstance(f, CryptoFinding) for f in findings)


def test_custom_rules_override(tmp_path):
    """Verify scan_file respects custom SourcePatternRule list when provided."""
    import re
    custom_rules = [
        SourcePatternRule(
            rule_id="custom-rule-1",
            pattern=re.compile(r"SpecialCryptoFunc"),
            algorithm_name="CustomAlgo",
            default_key_size="512",
            risk_reasoning="Custom primitive reasoning.",
            nist_standard="none",
            risk_level=QuantumRiskLevel.CRITICAL,
            asset_type=AssetType.ALGORITHM,
        )
    ]
    test_file = tmp_path / "custom.go"
    test_file.write_text("package main\nfunc main() {\n  SpecialCryptoFunc()\n}\n", encoding="utf-8")

    findings = scan_file(test_file, rules=custom_rules)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "CustomAlgo"
    assert findings[0].evidence[0].rule_id == "custom-rule-1"


# --- 5. Petty Tests: Dispatcher & File System Nitpicks ---

def test_dispatcher_ignores_non_source_files(tmp_path):
    """Petty: Verify dispatcher unconditionally ignores arbitrary non-source extensions."""
    for ext in (".txt", ".json", ".csv", ".md", ".exe", ".bin", ".go_backup", ".golang"):
        f = tmp_path / f"crypto{ext}"
        f.write_text("ed25519.GenerateKey(rand.Reader)\nmd5.New()", encoding="utf-8")
        assert scan_file(f) == [], f"Dispatcher improperly scanned unsupported extension {ext}!"


def test_dispatcher_case_insensitive_extension(tmp_path):
    """Petty: Verify dispatcher normalizes case and handles .GO and .Go identically."""
    for name in ("UPPER.GO", "Mixed.Go", "weird.gO"):
        f = tmp_path / name
        f.write_text("package main\nimport \"crypto/md5\"\nfunc main() { md5.New() }\n", encoding="utf-8")
        findings = scan_file(f)
        assert len(findings) == 1, f"Dispatcher failed on extension casing for {name}!"
        assert findings[0].algorithm_name == "MD5"


def test_dispatcher_non_existent_file(tmp_path):
    """Petty: Verify scan_file on a non-existent path gracefully returns empty list without raising."""
    phantom = tmp_path / "definitely_does_not_exist.go"
    assert scan_file(phantom) == []


def test_dispatcher_directory_passed_as_file(tmp_path):
    """Petty: Verify scan_file gracefully rejects a directory passed as file argument."""
    sub_dir = tmp_path / "somedir.go"
    sub_dir.mkdir()
    assert scan_file(sub_dir) == []


def test_dispatcher_scan_source_directory_non_existent():
    """Petty: Verify scan_source_directory on non-existent directory returns [] without throwing."""
    phantom = Path("/non/existent/path/for/quantum/scanner")
    assert scan_source_directory(phantom) == []


def test_dispatcher_empty_directory(tmp_path):
    """Petty: Verify scan_source_directory returns empty list for an empty directory."""
    assert scan_source_directory(tmp_path) == []


def test_dispatcher_scan_source_directory_nested_structure(tmp_path):
    """Petty: Verify scan_source_directory traverses deeply nested trees and records relative paths."""
    deep = tmp_path / "sub1" / "sub2" / "sub3"
    deep.mkdir(parents=True)
    go_file = deep / "deep_crypto.go"
    go_file.write_text("package main\nimport \"crypto/sha1\"\nfunc f() { sha1.New() }\n", encoding="utf-8")

    findings = scan_source_directory(tmp_path)
    assert len(findings) == 1
    rel_path = findings[0].evidence[0].file_path
    assert not rel_path.startswith("/")
    assert "sub1" in rel_path and "sub2" in rel_path and "sub3" in rel_path


# --- 6. Petty Tests: Adversarial Comments & String Literal Masking ---

def test_multiline_raw_backtick_string_ignored(tmp_path):
    """Petty: Verify multiline Go raw backtick strings containing crypto function calls produce 0 findings."""
    code = '''package main
import "fmt"

func main() {
	doc := `
		Here is an example:
		ed25519.GenerateKey(rand.Reader)
		rsa.GenerateKey(rand.Reader, 1024)
		md5.New()
		sha1.New()
	`
	fmt.Println(doc)
}
'''
    test_file = tmp_path / "raw_string.go"
    test_file.write_text(code, encoding="utf-8")
    findings = scan_go_file(test_file)
    assert len(findings) == 0, f"Spurious findings extracted from inside backtick raw string: {[f.algorithm_name for f in findings]}"


def test_escaped_quotes_inside_string_literal(tmp_path):
    """Petty: Verify escaped quotes inside string literals do not break string sanitization."""
    code = r'''package main
import "fmt"

func main() {
	msg := "Debug message: \"md5.Sum(data)\" was avoided here"
	fmt.Println(msg)
}
'''
    test_file = tmp_path / "escaped.go"
    test_file.write_text(code, encoding="utf-8")
    findings = scan_go_file(test_file)
    assert len(findings) == 0, "Failed to sanitize string containing escaped double quote!"


def test_inline_block_comment_before_real_call(tmp_path):
    """Petty: Verify inline block comment preceding a call preserves line number and extracts primitive."""
    code = """package main
import "crypto/md5"

func main() {
    /* inline block comment */ md5.Sum(nil)
}
"""
    test_file = tmp_path / "inline_comment.go"
    test_file.write_text(code, encoding="utf-8")
    findings = scan_go_file(test_file)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "MD5"
    assert findings[0].evidence[0].line_number == 5


def test_trailing_comment_on_call_line(tmp_path):
    """Petty: Verify trailing line comment does not affect primitive detection on that line."""
    code = """package main
import "crypto/rsa"
import "crypto/rand"

func main() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048) // RSA-2048 key generation here
    _ = key
}
"""
    test_file = tmp_path / "trailing_comment.go"
    test_file.write_text(code, encoding="utf-8")
    findings = scan_go_file(test_file)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "RSA-2048"
    assert findings[0].key_size == 2048


# --- 7. Petty Tests: Constant Resolution & Key Inference Nitpicks ---

def test_constant_resolution_word_boundary():
    """Petty: Verify resolve_constant enforces strict word boundaries (no prefix/suffix partial matches)."""
    code = """package main
const mykeyLen = 16
const keyLen = 32
const keyLengthLong = 64
"""
    assert resolve_constant(code, "keyLen") == "32"
    assert resolve_constant(code, "mykeyLen") == "16"
    assert resolve_constant(code, "keyLengthLong") == "64"


def test_constant_resolution_with_go_types():
    """Petty: Verify resolve_constant parses explicit Go typed constant declarations."""
    code = """package main
const KeySize int = 2048
const SaltLen uint32 = 16
const Iterations uint64 = 600000
"""
    assert resolve_constant(code, "KeySize") == "2048"
    assert resolve_constant(code, "SaltLen") == "16"
    assert resolve_constant(code, "Iterations") == "600000"


def test_constant_resolution_empty_or_special_chars():
    """Petty: Verify resolve_constant does not crash on empty, whitespace, or regex metacharacters."""
    assert resolve_constant("", "anyVar") == "unknown"
    assert resolve_constant("const x = 1", "") == "unknown"
    assert resolve_constant("const x = 1", "   ") == "unknown"
    assert resolve_constant("const x = 1", "$not_found") == "unknown"
    assert resolve_constant("const x = 1", "var.with.dots") == "unknown"
    assert resolve_constant("const x = 1", "key[index]") == "unknown"


def test_infer_key_size_from_literal_petty_cases():
    """Petty: Exhaustive check of infer_key_size_from_literal on edge cases."""
    # Hex bit calculations
    assert infer_key_size_from_literal("0123456789abcdef0123456789abcdef") == "128"
    assert infer_key_size_from_literal("0123456789abcdef0123456789abcdef0123456789abcdef") == "192"
    assert infer_key_size_from_literal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == "256"

    # Numeric byte counts
    assert infer_key_size_from_literal("16") == "128"
    assert infer_key_size_from_literal("24") == "192"
    assert infer_key_size_from_literal("32") == "256"

    # Direct bit counts
    assert infer_key_size_from_literal("128") == "128"
    assert infer_key_size_from_literal("256") == "256"
    assert infer_key_size_from_literal("1024") == "1024"
    assert infer_key_size_from_literal("2048") == "2048"
    assert infer_key_size_from_literal("4096") == "4096"

    # Byte slice syntax
    assert infer_key_size_from_literal('[]byte("0123456789012345")') == "128"

    # Empty and unknown
    assert infer_key_size_from_literal("") == "unknown"
    assert infer_key_size_from_literal("unknown") == "unknown"
    assert infer_key_size_from_literal(None) == "unknown"


# --- 8. Petty Tests: Pure Data Contract Invariants ---

def test_crypto_finding_pure_data_contract_no_monkey_patching(tmp_path):
    """Petty: Enforce that CryptoFinding models remain pure Pydantic contracts with ZERO monkey-patched properties."""
    code = """package main
import "crypto/md5"
func main() { md5.New() }
"""
    f = tmp_path / "contract.go"
    f.write_text(code, encoding="utf-8")
    findings = scan_go_file(f)
    assert len(findings) == 1
    finding = findings[0]

    # file_path and source_path must NOT be dynamically attached or patched onto CryptoFinding
    assert not hasattr(finding, "file_path"), "CryptoFinding has monkey-patched file_path property!"
    assert not hasattr(finding, "source_path"), "CryptoFinding has monkey-patched source_path property!"
    # file_path belongs strictly on Evidence
    assert hasattr(finding.evidence[0], "file_path")
    assert finding.evidence[0].file_path == "contract.go"


def test_crypto_finding_extra_fields_forbidden():
    """Petty: Verify that extra fields are strictly forbidden by ConfigDict(extra='forbid')."""
    from pydantic import ValidationError
    from scanner.models import Evidence

    with pytest.raises(ValidationError):
        CryptoFinding(
            algorithm_name="AES-256",
            source_type="source-code",
            observation="observed",
            evidence=[Evidence(file_path="main.go", rule_id="test", line_number=1)],
            unauthorized_field="illegal_value",
        )


def test_crypto_finding_empty_algorithm_name_rejected():
    """Petty: Verify that blank or whitespace algorithm_name raises ValidationError."""
    from pydantic import ValidationError
    from scanner.models import Evidence

    ev = [Evidence(file_path="main.go", rule_id="test", line_number=1)]
    with pytest.raises(ValidationError):
        CryptoFinding(algorithm_name="", source_type="source-code", observation="observed", evidence=ev)
    with pytest.raises(ValidationError):
        CryptoFinding(algorithm_name="   ", source_type="source-code", observation="observed", evidence=ev)


def test_evidence_non_empty_and_line_number_positive(tmp_path):
    """Petty: Verify all evidence line numbers are positive integers and paths are non-empty and relative."""
    findings = scan_source_directory(SAMPLE_GO_DIR)
    for finding in findings:
        assert len(finding.evidence) >= 1, "Evidence list must not be empty!"
        for ev in finding.evidence:
            assert ev.line_number is not None and ev.line_number > 0, f"Line number must be >= 1, got {ev.line_number}"
            assert ev.file_path and not ev.file_path.startswith("/"), f"Evidence file_path must be relative, got {ev.file_path}"
            assert ev.rule_id, "Rule ID must be non-empty"
            assert ev.matched_snippet, "Matched snippet must be non-empty"


# --- 9. Petty Tests: Rubric Risk Compliance Invariants ---

def test_classically_broken_primitives_are_strictly_critical(tmp_path):
    """Petty: Verify MD5, SHA-1, and AES-ECB are classified as Critical (never Medium or Safe)."""
    code = """package main
import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/aes"
)

var exportKey = []byte("0123456789ABCDEF")

func main() {
    _ = md5.New()
    _ = sha1.New()
    block, _ := aes.NewCipher(exportKey)
    block.Encrypt(nil, nil)
}
"""
    f = tmp_path / "broken.go"
    f.write_text(code, encoding="utf-8")
    findings = scan_go_file(f)

    algo_risks = {f.algorithm_name: f.quantum_risk for f in findings}
    assert algo_risks.get("MD5") == QuantumRiskLevel.CRITICAL, "MD5 must be Critical!"
    assert algo_risks.get("SHA-1") == QuantumRiskLevel.CRITICAL, "SHA-1 must be Critical!"
    assert any("ECB" in k and v == QuantumRiskLevel.CRITICAL for k, v in algo_risks.items()), "AES-ECB must be Critical!"


def test_symmetric_quantum_safe_primitives_are_never_critical(tmp_path):
    """Petty: Verify AES-256-GCM, HMAC-SHA256, PBKDF2, SHA-384, SHA-512 are NEVER Critical."""
    code = """package main
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
)

const keyLen = 32

func main() {
    k := make([]byte, keyLen)
    block, _ := aes.NewCipher(k)
    _, _ = cipher.NewGCM(block)
    _ = hmac.New(sha256.New, k)
    _ = sha512.New384()
    _ = sha512.New()
}
"""
    f = tmp_path / "safe.go"
    f.write_text(code, encoding="utf-8")
    findings = scan_go_file(f)

    for f in findings:
        assert f.quantum_risk != QuantumRiskLevel.CRITICAL, (
            f"Quantum safe/resistant primitive {f.algorithm_name} must NEVER be Critical!"
        )
        assert f.quantum_risk == QuantumRiskLevel.SAFE, (
            f"Expected Safe for {f.algorithm_name}, got {f.quantum_risk}"
        )


def test_shor_vulnerable_asymmetric_primitives_are_strictly_critical(tmp_path):
    """Petty: Verify RSA (any key size), Ed25519, ECDSA, Curve25519 are strictly Critical."""
    code = """package main
import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/ed25519"
    "crypto/ecdsa"
    "crypto/elliptic"
    "golang.org/x/crypto/curve25519"
)

func main() {
    _, _ = rsa.GenerateKey(rand.Reader, 4096)
    _, _, _ = ed25519.GenerateKey(rand.Reader)
    _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _, _ = curve25519.X25519(nil, nil)
}
"""
    f = tmp_path / "asym.go"
    f.write_text(code, encoding="utf-8")
    findings = scan_go_file(f)

    assert len(findings) >= 4
    for f in findings:
        assert f.quantum_risk == QuantumRiskLevel.CRITICAL, (
            f"Shor-vulnerable asymmetric primitive {f.algorithm_name} must be Critical!"
        )


def test_aes_128_gcm_is_strictly_medium(tmp_path):
    """Petty: Verify AES-128 in GCM mode is classified strictly as Medium."""
    code = """package main
import (
    "crypto/aes"
    "crypto/cipher"
)

const keyLen = 16

func main() {
    k := make([]byte, keyLen)
    block, _ := aes.NewCipher(k)
    gcm, _ := cipher.NewGCM(block)
    _ = gcm
}
"""
    f = tmp_path / "aes128gcm.go"
    f.write_text(code, encoding="utf-8")
    findings = scan_go_file(f)

    assert len(findings) == 1
    aes_f = findings[0]
    assert "AES-128" in aes_f.algorithm_name
    assert aes_f.mode == "GCM"
    assert aes_f.quantum_risk == QuantumRiskLevel.MEDIUM, "AES-128-GCM must be Medium!"


# --- 10. Petty Tests: Multi-Finding & Corrupted Encoding Resilience ---

def test_multiple_primitives_on_same_line(tmp_path):
    """Petty: Verify multiple cryptographic primitives on the exact same line are both extracted."""
    code = """package main
import "crypto/md5"
import "crypto/sha1"

func main() {
    m := md5.New(); s := sha1.New(); _ = m; _ = s
}
"""
    f = tmp_path / "same_line.go"
    f.write_text(code, encoding="utf-8")
    findings = scan_go_file(f)

    assert len(findings) == 2
    algos = {f.algorithm_name for f in findings}
    assert "MD5" in algos
    assert "SHA-1" in algos
    # Both must point to line 6
    assert findings[0].evidence[0].line_number == 6
    assert findings[1].evidence[0].line_number == 6


def test_corrupted_encoding_file_resilience(tmp_path):
    """Petty: Verify non-UTF-8 corrupt byte sequence does not crash scanner and captures primitive."""
    bad_bytes = b"package main\n\xff\xfe\x00\x00\nfunc f() { md5.New() }\n\x80\x81\x82\n"
    f = tmp_path / "corrupted.go"
    f.write_bytes(bad_bytes)

    findings = scan_go_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm_name == "MD5"


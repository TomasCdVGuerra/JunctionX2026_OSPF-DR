"""Python and Java through canonical discovery, risk, dispatcher and exports."""
import json
from pathlib import Path

import jsonschema
import pytest

import dashboard
from scanner.models import CryptoFinding
from scanner.source_scanner import scan_file
from scanner.risk import enrich_finding


@pytest.mark.parametrize("extension,source,name,operation,quantum,classical", [
    ("py", "import hashlib as h\nx = h.md5(b'data')", "MD5", "digest", "medium", "critical"),
    ("py", "import hmac, hashlib\nx = hmac.new(key, data, hashlib.sha1)", "HMAC-SHA-1", "mac", "unknown", "unknown"),
    ("py", "import hashlib\nx = hashlib.pbkdf2_hmac('sha256', password, salt, rounds)", "PBKDF2-HMAC-SHA-256", "kdf", "unknown", "unknown"),
    ("py", "from Crypto.Cipher import AES\nMODE = AES.MODE_ECB\nx = AES.new(key, MODE)", "AES", "unknown", "unknown", "critical"),
    ("py", "from cryptography.hazmat.primitives.asymmetric import rsa\nBITS = 3072\nx = rsa.generate_private_key(65537, BITS)", "RSA", "keygen", "critical", "safe"),
    ("java", 'import java.security.MessageDigest; class X { void f() { MessageDigest.getInstance("SHA-256"); } }', "SHA-256", "digest", "medium", "safe"),
    ("java", 'import javax.crypto.Mac; class X { void f() { Mac.getInstance("HmacSHA1"); } }', "HMAC-SHA-1", "mac", "unknown", "unknown"),
    ("java", 'import javax.crypto.SecretKeyFactory; class X { void f() { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); } }', "PBKDF2-HMAC-SHA-256", "kdf", "unknown", "unknown"),
    ("java", 'import javax.crypto.Cipher; class X { void f() { Cipher.getInstance("AES/ECB/PKCS5Padding"); } }', "AES", "unknown", "unknown", "critical"),
    ("java", 'import java.security.KeyPairGenerator; class X { void f() { KeyPairGenerator.getInstance("RSA"); } }', "RSA", "keygen", "critical", "unknown"),
])
def test_language_discovery_and_risk(tmp_path, extension, source, name, operation, quantum, classical):
    path = tmp_path / f"example.{extension}"
    path.write_text(source, encoding="utf-8")
    findings = scan_file(path, base_dir=tmp_path)
    assert len(findings) == 1
    original = findings[0]
    assert isinstance(original, CryptoFinding)
    assert original.algorithm_name == name
    assert original.crypto_function.value == operation
    assert original.quantum_risk.value == original.classical_risk.value == "unknown"
    assert original.evidence[0].file_path == path.name
    assert original.evidence[0].line_number > 0
    enriched = enrich_finding(original)
    assert enriched.quantum_risk.value == quantum
    assert enriched.classical_risk.value == classical


def test_real_language_uploads_have_no_fallback_and_valid_cbom(monkeypatch):
    monkeypatch.setattr(dashboard, "_scan_source_file_fallback", lambda path: pytest.fail("Do not use fallback with functional scanners"))
    class Upload:
        def __init__(self, name, content):
            self.name, self.content = name, content
        def getvalue(self):
            return self.content.encode()
    cbom, warnings = dashboard.scan_uploaded_files([
        Upload("hash.py", "import hashlib\nhashlib.md5(data)"),
        Upload("Hash.java", 'import java.security.MessageDigest; class Hash { void f() { MessageDigest.getInstance("MD5"); } }'),
        Upload("clean.py", "x = 1"),
    ])
    assert not warnings
    df = dashboard.load_findings_dataframe(cbom)
    assert len(df) == 2
    assert (df["Scanner source"] == "real: scanner.source_scanner").all()
    assert (df["Classical Risk"] == "Critical").all()
    schema = json.loads((Path(__file__).parent / "fixtures/bom-1.6.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(cbom, schema)

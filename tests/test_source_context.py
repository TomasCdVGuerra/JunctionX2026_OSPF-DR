"""Composite constructions and scoped receiver configuration regressions."""
from pathlib import Path

import pytest

from scanner.source_scanner import scan_file
from scanner.risk import enrich_finding


@pytest.mark.parametrize("source,name,mode,operation,size", [
    ("from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nx = Cipher(algorithms.AES(key), modes.ECB())", "AES", "ECB", "unknown", None),
    ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nx = AESGCM(key).encrypt(nonce, data, None)", "AES", "GCM", "encrypt", None),
    ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nx = AESGCM(key).decrypt(nonce, data, None)", "AES", "GCM", "decrypt", None),
    ("from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\nx = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)", "PBKDF2-HMAC-SHA-256", None, "kdf", None),
    ("from cryptography.hazmat.primitives import hashes\nx = hashes.SHA256()", "SHA-256", None, "unknown", None),
    ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nKEY = b'0123456789ABCDEF'\nx = AESGCM(KEY)", "AES", "GCM", "unknown", 128),
    ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nkey = b'0123456789ABCDEF'\ndef f(key):\n    return AESGCM(key)", "AES", "GCM", "unknown", None),
])
def test_python_construction_not_disconnected_children(tmp_path, source, name, mode, operation, size):
    path = tmp_path / "example.py"
    path.write_text(source, encoding="utf-8")
    findings = scan_file(path)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.algorithm_name, finding.mode, finding.crypto_function.value, finding.key_size) == (name, mode, operation, size)
    if mode == "ECB":
        assert enrich_finding(finding).classical_risk.value == "critical"
    if operation == "kdf":
        assessed = enrich_finding(finding)
        assert assessed.quantum_risk.value == assessed.classical_risk.value == "unknown"


def test_java_generator_constants_and_distinct_receivers(tmp_path):
    path = tmp_path / "X.java"
    path.write_text('''import java.security.KeyPairGenerator;
class X {
 static final int BITS = 1024;
 void first() {
  KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
  generator.initialize(BITS);
 }
 void second() {
  KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
  other.initialize(4096);
 }
}''', encoding="utf-8")
    first, second = scan_file(path)
    assert first.key_size == 1024
    assert enrich_finding(first).classical_risk.value == "critical"
    assert second.key_size is None


def test_java_verify_and_cipher_key_binding(tmp_path):
    path = tmp_path / "X.java"
    path.write_text('''import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
class X {
 static final byte[] KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
 void f() {
  Signature signature = Signature.getInstance("SHA1withRSA");
  signature.initVerify(publicKey);
  SecretKeySpec spec = new SecretKeySpec(KEY, "AES");
  Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
  cipher.init(Cipher.ENCRYPT_MODE, spec);
 }
}''', encoding="utf-8")
    signature, key, cipher = scan_file(path)
    assert signature.crypto_function.value == "verify"
    assert key.key_size == cipher.key_size == 128
    assert cipher.crypto_function.value == "encrypt"
    assert enrich_finding(cipher).classical_risk.value == "critical"


def test_real_sample_context():
    root = Path(__file__).resolve().parents[1] / "support-materials/sample-repos"
    export = scan_file(root / "python/report_export.py")
    assert len(export) == 1 and export[0].mode == "ECB"
    assert enrich_finding(export[0]).classical_risk.value == "critical"
    credentials = scan_file(root / "python/member_credentials.py")
    assert len(credentials) == 2
    assert all(f.crypto_function.value == "kdf" for f in credentials)
    transfer = scan_file(root / "python/secure_transfer.py")
    assert {f.crypto_function.value for f in transfer} == {"encrypt", "decrypt"}
    receipt = scan_file(root / "java/ReceiptSigner.java")
    assert receipt[0].key_size == 1024
    assert {f.crypto_function.value for f in receipt[1:]} == {"sign", "verify"}

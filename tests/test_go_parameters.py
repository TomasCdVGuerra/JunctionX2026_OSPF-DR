"""Avoid fabricated parameters before central risk assessment."""
import pytest

from scanner.go_scanner import scan_go_file
from scanner.risk import enrich_finding


@pytest.mark.parametrize("source,name,size,mode", [
    ("rsa.GenerateKey(rand.Reader, configuredSize)", "RSA", None, None),
    ("const bits = 3072\nrsa.GenerateKey(rand.Reader, bits)", "RSA-3072", 3072, None),
    ("ecdsa.GenerateKey(elliptic.P384(), rand.Reader)", "ECDSA", 384, None),
    ("ecdsa.GenerateKey(selectedCurve, rand.Reader)", "ECDSA", None, None),
    ("aes.NewCipher(key)", "AES", None, None),
    ("key := make([]byte, 32)\naes.NewCipher(key)", "AES-256", 256, None),
])
def test_resolved_and_unresolved_parameters(tmp_path, source, name, size, mode):
    path = tmp_path / "parameters.go"
    path.write_text(source, encoding="utf-8")
    finding = scan_go_file(path)[0]
    assert (finding.algorithm_name, finding.key_size, finding.mode) == (name, size, mode)
    if size is None:
        assert enrich_finding(finding).classical_risk.value == "unknown"

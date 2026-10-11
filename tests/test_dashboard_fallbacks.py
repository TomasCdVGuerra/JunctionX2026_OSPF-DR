"""Fallback discovery must not bypass risk enrichment or invent context."""
import json

import pytest

import dashboard
from scanner.dashboard_fallbacks import (
    scan_cloud_file,
    scan_pcap_file,
    scan_source_file,
)


@pytest.mark.parametrize("source,name,size,quantum,classical", [
    ("rsa.GenerateKey(rand.Reader, configuredSize)", "RSA", None, "Critical", "Unknown"),
    ("rsa.generate_private_key(public_exponent=65537, key_size=3072)", "RSA", 3072, "Critical", "Safe"),
    ('KeyPairGenerator.getInstance("RSA")', "RSA", None, "Critical", "Unknown"),
    ("aes.NewCipher(key)", "AES", None, "Unknown", "Unknown"),
    ('Cipher.getInstance("AES/ECB/PKCS5Padding")', "AES", None, "Unknown", "Critical"),
    ("pbkdf2_hmac('sha256', password, salt, iterations)", "PBKDF2", None, "Unknown", "Unknown"),
    ("hashlib.md5(data)", "MD5", None, "Medium", "Critical"),
])
def test_source_fallback_uses_central_assessment(tmp_path, source, name, size, quantum, classical):
    path = tmp_path / "example.py"
    path.write_text(source, encoding="utf-8")
    findings = scan_source_file(path)
    assert len(findings) == 1
    original = findings[0]
    assert original.algorithm_name == name
    assert original.key_size == size
    assert original.quantum_risk.value == "unknown"
    before = original.model_dump()
    row = dashboard.load_findings_dataframe(dashboard._build_cbom_from_findings(findings)).iloc[0]
    assert original.model_dump() == before
    assert row["Quantum Risk"] == quantum
    assert row["Classical Risk"] == classical
    assert row["Scanner source"] == "FALLBACK heuristic"
    assert row["Recommendation"] != "unknown"
    assert "Risco clássico" in row["Description"]


def test_cloud_fallback_missing_metadata_and_unknown_policy(tmp_path):
    path = tmp_path / "cloud.json"
    path.write_text(json.dumps({
        "Region": "cn-north-1",
        "Keys": [{"KeySpec": "SYMMETRIC_DEFAULT"}, {"KeySpec": "ECC_FUTURE"}],
        "Certificates": [{}],
        "LoadBalancers": [{"Listeners": [{"Protocol": "HTTPS", "SslPolicy": "UnknownPolicy"}]}],
    }), encoding="utf-8")
    findings = scan_cloud_file(path)
    assert len(findings) == 4
    assert all(f.key_size is None and f.mode is None for f in findings)
    assert all(f.evidence[0].json_path and f.evidence[0].line_number is None for f in findings)
    rows = dashboard.load_findings_dataframe(dashboard._build_cbom_from_findings(findings))
    assert (rows["Quantum Risk"] == "Unknown").all()
    assert (rows["Classical Risk"] == "Unknown").all()


def test_pcap_marker_does_not_invent_negotiation(tmp_path):
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"\x16\x03\x01\x00\xa5")
    finding = scan_pcap_file(path)[0]
    assert finding.algorithm_name == "TLS"
    assert finding.observation == "observed"
    assert finding.evidence[0].packet_number is None
    row = dashboard.load_findings_dataframe(dashboard._build_cbom_from_findings([finding])).iloc[0]
    assert row["Quantum Risk"] == row["Classical Risk"] == "Unknown"
    assert row["Packet Number"] == "N/A"


def test_uploaded_fallback_routes_through_engine(monkeypatch):
    monkeypatch.setattr(dashboard, "_get_source_scanner_file", lambda: None)

    class Upload:
        name = "unresolved.go"
        def getvalue(self):
            return b"rsa.GenerateKey(rand.Reader, configuredSize)"

    cbom, warnings = dashboard.scan_uploaded_files([Upload()])
    assert not warnings
    row = dashboard.load_findings_dataframe(cbom).iloc[0]
    assert row["Classical Risk"] == "Unknown"
    assert row["Scanner source"] == "FALLBACK heuristic"
    assert row["Source Path"] == "unresolved.go"

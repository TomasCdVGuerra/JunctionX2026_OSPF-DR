"""Public network entrypoint through upload, protocol assessment and CBOM."""
import json
from pathlib import Path

import jsonschema
import pytest

import dashboard
from scanner import pcap_scanner
from scanner.network_scanner import pcap_scanner as implementation
from scanner.network_scanner.parser.tshark_parser import PcapParserError


def metadata():
    return {
        "tls_sessions": [{
            "packet_number": 7, "handshake_type": "Client Hello",
            "tls_version": "TLS 1.2", "supported_versions": ["TLS 1.2"],
            "cipher_suites": ["0xc02f"], "selected_cipher": None,
            "supported_groups": [], "key_share_groups": [],
            "selected_group": None, "signature_algorithms": [],
        }],
        "ssh_sessions": [],
        "cleartext_traffic": [{"packet_number": 8, "protocol": "HTTP", "http_method": "GET"}],
    }


def test_public_entrypoint_preserves_network_assessment_and_originals(monkeypatch):
    original = implementation.analyze_cleartext(metadata()["cleartext_traffic"], Path("capture.pcap"))[0]
    before = original.model_dump()
    monkeypatch.setattr(implementation, "scan", lambda path: [original])
    result = pcap_scanner.scan(Path("capture.pcap"))[0]
    assert original.model_dump() == before
    assert result.classical_risk.value == "critical"
    assert result.quantum_risk.value == "unknown"
    assert result.evidence[:-1] == original.evidence


def test_network_upload_uses_real_parser_once_and_keeps_protocol_context(monkeypatch):
    calls = []
    def parse(path):
        calls.append(path)
        return metadata()
    monkeypatch.setattr(implementation, "parse_network_pcap", parse)
    monkeypatch.setattr(dashboard, "_scan_pcap_file_fallback", lambda path: pytest.fail("Real scanner must be used"))

    class Upload:
        name = "capture.pcap"
        def getvalue(self):
            return b"fixture"

    cbom, warnings = dashboard.scan_uploaded_files([Upload()])
    assert not warnings
    assert len(calls) == 1
    df = dashboard.load_findings_dataframe(cbom)
    assert (df["Scanner source"] == "real: scanner.pcap_scanner").all()
    assert (df["Source Path"] == "capture.pcap").all()
    cleartext = df[df["Algorithm"] == "Cleartext"].iloc[0]
    assert cleartext["Classical Risk"] == "Critical"
    assert cleartext["Quantum Risk"] == "Unknown"
    assert cleartext["Packet Number"] == "8"
    assert "Plaintext" in cleartext["Description"]
    tls = df[df["Algorithm"] == "TLS 1.2"].iloc[0]
    assert tls["Classical Risk"] == "Unknown"
    assert tls["Observation"] == "advertised"
    aes = df[df["Algorithm"] == "AES"].iloc[0]
    assert aes["NIST References"] == "FIPS 197; SP 800-38D"
    assert aes["Observation"] == "advertised"
    schema = json.loads((Path(__file__).parent / "fixtures/bom-1.6.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(cbom, schema)


def test_missing_tshark_is_visible_without_silent_fallback(monkeypatch):
    def fail(path):
        raise PcapParserError("TShark unavailable; define TSHARK_PATH")
    monkeypatch.setattr(implementation, "parse_network_pcap", fail)
    monkeypatch.setattr(dashboard, "_scan_pcap_file_fallback", lambda path: pytest.fail("Failed real scan must not become fallback"))

    class Upload:
        name = "capture.pcap"
        def getvalue(self):
            return b"fixture"

    cbom, warnings = dashboard.scan_uploaded_files([Upload()])
    assert cbom is None
    assert any("TShark unavailable" in warning for warning in warnings)


def test_heuristic_network_finding_still_uses_central_engine(tmp_path):
    path = tmp_path / "hint.pcap"
    path.write_bytes(b"TLS")
    finding = dashboard._scan_pcap_file_fallback(path)[0]
    row = dashboard.load_findings_dataframe(dashboard._build_cbom_from_findings([finding])).iloc[0]
    assert row["Quantum Risk"] == row["Classical Risk"] == "Unknown"
    assert row["Scanner source"] == "FALLBACK heuristic"

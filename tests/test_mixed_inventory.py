"""Mixed upload through real Cloud/Go scanners and real network analyzers.

Only TShark metadata extraction is replaced, so this regression runs on team
machines without the external executable. Real PCAP validation is separate.
"""
import json
from pathlib import Path

import jsonschema

import dashboard
from scanner.network_scanner import pcap_scanner


ROOT = Path(__file__).resolve().parents[1]


class Upload:
    def __init__(self, path):
        self.path = path
        self.name = path.name

    def getvalue(self):
        return self.path.read_bytes()


def test_mixed_upload_exports_all_sources_and_preserves_protocol_risk(monkeypatch):
    monkeypatch.setattr(pcap_scanner, "parse_network_pcap", lambda path: {
        "tls_sessions": [], "ssh_sessions": [],
        "cleartext_traffic": [{"protocol": "HTTP", "packet_number": 8}],
    })
    paths = sorted((ROOT / "support-materials/cloud-posture").glob("*.json"))
    paths += sorted((ROOT / "support-materials/sample-repos/go").rglob("*.go"))
    paths += [ROOT / "support-materials/network-capture/network.pcap"]
    cbom, warnings = dashboard.scan_uploaded_files([Upload(path) for path in paths])
    assert not warnings
    df = dashboard.load_findings_dataframe(cbom)
    assert set(df["Source Type"]) == {"cloud-posture", "source-code", "network-capture"}
    cloud = df[df["Source Type"] == "cloud-posture"]
    assert len(cloud) == 99
    assert cloud["Quantum Risk"].value_counts().to_dict() == {"Critical": 76, "Unknown": 19, "Safe": 4}
    go = df[df["Source Type"] == "source-code"]
    assert len(go) > 0
    assert (go["Scanner source"] == "real: scanner.source_scanner").all()
    assert (go["Line Number"] != "N/A").all()
    network = df[df["Source Type"] == "network-capture"]
    assert len(network) == 1
    assert network.iloc[0]["Classical Risk"] == "Critical"
    assert network.iloc[0]["Quantum Risk"] == "Unknown"
    assert network.iloc[0]["Packet Number"] == "8"
    assert set(df["Source Path"]).issubset({path.name for path in paths})
    assert (df["Recommendation"] != "unknown").all()
    references = [component["bom-ref"] for component in cbom["components"]]
    assert len(set(references)) == len(references)
    schema = json.loads((ROOT / "tests/fixtures/bom-1.6.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(cbom, schema)

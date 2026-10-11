"""Explained, scoped expectations for Cloud and packets in the supplied capture."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

import pytest

from scanner.cloud_scanner import scan
from scanner.risk import enrich_finding
from scanner.network_scanner.analyser.tls_analyzer import analyze_tls
from scanner.network_scanner.analyser.ssh_analyzer import analyze_ssh
from scanner.network_scanner.analyser.cleartext_analyzer import analyze_cleartext
from scanner.network_scanner.parser.tshark_parser import (
    PcapParserError, find_tshark_binary, parse_network_pcap,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
CLOUD = json.loads((FIXTURES / "expected_cloud_findings.json").read_text(encoding="utf-8"))
NETWORK = json.loads((FIXTURES / "expected_network_findings.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CLOUD["cases"], ids=lambda case: case["file"])
def test_reviewed_cloud_inventory(case):
    findings = [enrich_finding(f) for f in scan(ROOT / "support-materials/cloud-posture" / case["file"])]
    if "scope" in case:
        scope = case["scope"]
        findings = [f for f in findings if f.evidence[0].json_path == scope["json_path"]
                    and f.algorithm_name in scope["algorithms"]]
    actual = Counter((f.evidence[0].json_path, f.algorithm_name, f.key_size, f.mode,
                      f.crypto_function.value, f.quantum_risk.value, f.classical_risk.value) for f in findings)
    expected = Counter(tuple(row) for row in case["expected"])
    assert actual == expected, {"reason": case["reason"], "missing": expected - actual, "unexpected": actual - expected}
    assert all(f.observation == "configured" for f in findings)


def _check_network_case(case, metadata):
    analyzer = {"tls_sessions": analyze_tls, "ssh_sessions": analyze_ssh,
                "cleartext_traffic": analyze_cleartext}[case["kind"]]
    findings = analyzer(metadata, ROOT / "support-materials/network-capture/network.pcap")
    actual = Counter((f.evidence[0].packet_number, f.algorithm_name, f.key_size, f.mode,
                      f.observation, f.crypto_function.value, f.quantum_risk.value, f.classical_risk.value)
                     for f in findings)
    expected = Counter(tuple(row) for row in case["expected"])
    assert actual == expected, {"reason": case["reason"], "missing": expected - actual, "unexpected": actual - expected}


@pytest.mark.parametrize("case", NETWORK["cases"], ids=lambda case: case["kind"])
def test_reviewed_network_findings_without_external_dependency(case):
    _check_network_case(case, case["metadata"])


def test_reviewed_packets_through_real_tshark():
    try:
        find_tshark_binary()
    except PcapParserError as exc:
        if os.environ.get("QUANTUMTRACE_REQUIRE_TSHARK_REVIEW") == "1":
            pytest.fail(f"Real TShark validation required: {exc}")
        pytest.skip("TShark unavailable; offline reviewed packet expectations are still tested")
    capture = ROOT / "support-materials/network-capture/network.pcap"
    assert hashlib.sha256(capture.read_bytes()).hexdigest() == NETWORK["capture_sha256"]
    actual = parse_network_pcap(str(capture))
    for case in NETWORK["cases"]:
        packets = {entry["packet_number"] for entry in case["metadata"]}
        selected = [entry for entry in actual[case["kind"]] if entry["packet_number"] in packets]
        assert selected == case["metadata"], f"Reviewed metadata changed: {case['kind']}"
        _check_network_case(case, selected)

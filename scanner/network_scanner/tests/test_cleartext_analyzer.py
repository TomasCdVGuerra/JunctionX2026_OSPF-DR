"""Cleartext assessment with real shared models and sanitized packet evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scanner.models import AssetType, CryptoFinding, CryptoFunction, QuantumRiskLevel
from scanner.network_scanner.analyser.cleartext_analyzer import analyze_cleartext


PATH = Path("captured.pcap")


def test_cleartext_preserves_packet_and_endpoints_but_excludes_credentials():
    entry = {
        "packet_number": 8, "stream_id": "0", "protocol": "HTTP", "http_method": "GET",
        "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
        "source_port": "50100", "destination_port": "80",
        "http_host": "username:secret@example.com", "http_uri": "/login?token=secret",
        "matched_snippet": "Authorization: Bearer secret", "payload": "password=secret",
    }
    [finding] = analyze_cleartext([entry], PATH)
    assert finding.algorithm_name == "Cleartext"
    assert finding.asset_type == AssetType.PROTOCOL
    assert finding.classical_risk == QuantumRiskLevel.CRITICAL
    assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
    assert finding.evidence[0].file_path == str(PATH)
    assert finding.evidence[0].packet_number == 8
    snippet = finding.evidence[0].matched_snippet
    context = json.loads(snippet)
    assert context["source_ip"] == "10.0.0.1"
    assert context["destination_ip"] == "10.0.0.2"
    assert context["source_port"] == "50100"
    assert context["destination_port"] == "80"
    assert context["http_host"] == "example.com"
    assert "secret" not in snippet and "username" not in snippet and "token" not in snippet
    assert not {"http_uri", "matched_snippet", "payload"}.intersection(context)


def test_cleartext_requires_protocol_evidence_not_a_standard_port():
    assert analyze_cleartext([{"destination_port": "80", "payload": "GET /"}], PATH) == []
    for protocol in ("PostgreSQL", "LDAP", "FTP", "Telnet", "SMTP"):
        [finding] = analyze_cleartext([{"protocol": protocol, "matched_snippet": "PASS secret"}], PATH)
        assert finding.protocol == protocol
        assert "secret" not in finding.evidence[0].matched_snippet


@pytest.mark.parametrize("protocol", [None, "", "  \t\n", 80, True, [], {}])
def test_invalid_protocol_does_not_produce_a_cleartext_finding(protocol):
    assert analyze_cleartext([{"protocol": protocol, "destination_port": "80"}], PATH) == []


def test_empty_input_returns_no_findings():
    assert analyze_cleartext([], PATH) == []


@pytest.mark.parametrize("packet", [None, 0, "unknown"])
def test_cleartext_without_valid_packet_number_preserves_missing_evidence(packet):
    [finding] = analyze_cleartext([{"protocol": "HTTP", "packet_number": packet}], PATH)
    assert finding.evidence[0].packet_number is None
    assert "packet_number" not in json.loads(finding.evidence[0].matched_snippet)


def test_cleartext_analysis_does_not_mutate_metadata():
    entries = [{"protocol": " HTTP ", "http_host": "username:secret@example.com",
                "payload": "secret", "untrusted_extra": {"password": "secret"}}]
    before = copy.deepcopy(entries)
    [finding] = analyze_cleartext(entries, PATH)
    context = json.loads(finding.evidence[0].matched_snippet)
    assert finding.protocol == context["protocol"] == "HTTP"
    assert context["http_host"] == "example.com"
    assert entries == before


def test_cleartext_serializes_observed_protocol_with_explained_risks():
    [finding] = analyze_cleartext([{"protocol": "HTTP", "packet_number": 12}], PATH)
    assert finding.observation == "observed"
    assert finding.crypto_function == CryptoFunction.UNKNOWN
    assert finding.key_size is None and finding.mode is None and finding.padding is None
    assert finding.evidence[0].risk_reasoning
    assert finding.recommendation
    payload = json.loads(json.dumps(finding.to_dict()))
    assert payload["source_type"] == "network-capture"
    assert payload["asset_type"] == "protocol"
    assert payload["quantum_risk"] == "unknown"
    assert payload["classical_risk"] == "critical"
    assert "key_size" not in payload
    assert CryptoFinding.model_validate(payload) == finding

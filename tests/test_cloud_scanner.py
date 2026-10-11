import json
from pathlib import Path
import pytest

from scanner.cloud_scanner import parse_kms_keys, parse_acm_certificates, parse_load_balancers, load_elb_policy_map, scan
from scanner.models import AssetType, QuantumRiskLevel, CryptoFunction


CLOUD_DIR = (
    Path(__file__).resolve().parents[1]
    / "support-materials"
    / "cloud-posture"
)


def test_kms_inventory():
    findings = scan(CLOUD_DIR / "kms_key_inventory.json")

    assert len(findings) == 10

    first = findings[0]
    assert first.algorithm_name == "RSA"
    assert first.key_size == 2048
    assert first.asset_type == AssetType.KEY
    assert first.source_type == "cloud-posture"
    assert first.observation == "configured"


def test_kms_symmetric_configuration():
    findings = scan(CLOUD_DIR / "kms_key_inventory.json")

    symmetric = [
        finding for finding in findings
        if finding.algorithm_name == "AES"
    ]

    assert len(symmetric) == 4

    for finding in symmetric:
        assert finding.key_size == 256
        assert finding.mode == "GCM"
        assert len(finding.evidence) == 2
        assert finding.evidence[1].json_path == "$.Region"


def test_kms_evidence_preserves_resource():
    filepath = CLOUD_DIR / "kms_key_inventory.json"
    original = json.loads(filepath.read_text(encoding="utf-8"))
    findings = scan(filepath)

    for index, finding in enumerate(findings):
        evidence = finding.evidence[0]

        assert evidence.file_path == str(filepath)
        assert evidence.json_path == f"$.Keys[{index}]"
        assert evidence.rule_id == "AWS-KMS-KEY-SPEC"
        assert json.loads(evidence.matched_snippet) == original["Keys"][index]


def test_kms_risk_is_not_classified_by_scanner():
    findings = scan(CLOUD_DIR / "kms_key_inventory.json")

    for finding in findings:
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN
        assert finding.recommendation is None


@pytest.mark.parametrize(
    "key",
    [
        {},
        {"KeySpec": "FUTURE_KEY_SPEC"},
        {"KeySpec": "SYMMETRIC_DEFAULT"},
    ],
)
def test_unknown_key_parameters_are_not_guessed(key):
    finding = parse_kms_keys(
        {"Keys": [key]},
        Path("kms.json"),
    )[0]

    assert finding.algorithm_name == key.get("KeySpec", "unknown")
    assert finding.key_size is None
    assert finding.mode is None
    assert finding.oid is None


@pytest.mark.parametrize("state", ["Disabled", "PendingDeletion"])
def test_inactive_keys_remain_in_inventory(state):
    key = {
        "KeySpec": "RSA_2048",
        "KeyState": state,
        "KeyArn": "arn:example",
    }

    findings = parse_kms_keys({"Keys": [key]}, Path("kms.json"))

    assert len(findings) == 1
    assert json.loads(findings[0].evidence[0].matched_snippet) == key


def test_china_symmetric_configuration():
    finding = parse_kms_keys(
        {
            "Region": "cn-north-1",
            "Keys": [{"KeySpec": "SYMMETRIC_DEFAULT"}],
        },
        Path("kms.json"),
    )[0]

    assert finding.algorithm_name == "SM4"
    assert finding.key_size == 128
    assert finding.mode is None
    assert json.loads(finding.evidence[1].matched_snippet) == "cn-north-1"


def test_empty_inventory():
    assert parse_kms_keys({"Keys": []}, Path("kms.json")) == []


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"Keys": None},
        {"Keys": {}},
        {"Keys": [42]},
    ],
)
def test_invalid_inventory_shape(data):
    with pytest.raises(ValueError):
        parse_kms_keys(data, Path("kms.json"))


@pytest.mark.parametrize("key_spec", ["", "   ", 2048, []])
def test_invalid_key_spec(key_spec):
    with pytest.raises(ValueError, match="KeySpec"):
        parse_kms_keys(
            {"Keys": [{"KeySpec": key_spec}]},
            Path("kms.json"),
        )


def test_invalid_json_file(tmp_path):
    filepath = tmp_path / "invalid.json"
    filepath.write_text('{"Keys": [', encoding="utf-8")

    with pytest.raises(ValueError, match="JSON inválido"):
        scan(filepath)


def test_unsupported_export(tmp_path):
    filepath = tmp_path / "other.json"
    filepath.write_text('{"OtherResources": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="ainda não suportado"):
        scan(filepath)


def test_acm_public_key_inventory():
    findings = [
        finding
        for finding in scan(CLOUD_DIR / "acm_certificates.json")
        if finding.asset_type == AssetType.CERTIFICATE
    ]

    assert [(f.algorithm_name, f.key_size) for f in findings] == [
        ("RSA", 2048),
        ("EC", 256),
        ("RSA", 2048),
        ("EC", 384),
        ("RSA", 2048),
    ]

    for finding in findings:
        assert finding.asset_type == AssetType.CERTIFICATE
        assert finding.source_type == "cloud-posture"
        assert finding.observation == "configured"
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN


def test_acm_evidence_preserves_resource():
    filepath = CLOUD_DIR / "acm_certificates.json"
    original = json.loads(filepath.read_text(encoding="utf-8"))

    findings = [
        finding
        for finding in scan(filepath)
        if finding.asset_type == AssetType.CERTIFICATE
    ]

    for index, finding in enumerate(findings):
        evidence = finding.evidence[0]

        assert evidence.file_path == str(filepath)
        assert evidence.json_path == f"$.Certificates[{index}]"
        assert evidence.rule_id == "AWS-ACM-PUBLIC-KEY"
        assert json.loads(evidence.matched_snippet) == (
            original["Certificates"][index]
        )


def test_acm_signature_algorithms():
    findings = scan(CLOUD_DIR / "acm_certificates.json")
    signatures = [
        finding
        for finding in findings
        if finding.crypto_function == CryptoFunction.SIGN
    ]

    assert len(findings) == 10
    assert [f.algorithm_name for f in signatures] == [
        "SHA256WITHRSA",
        "ECDSA_WITH_SHA256",
        "SHA256WITHRSA",
        "ECDSA_WITH_SHA384",
        "SHA1WITHRSA",
    ]

    for finding in signatures:
        assert finding.asset_type == AssetType.ALGORITHM
        assert finding.key_size is None
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN


def test_acm_signature_evidence():
    filepath = CLOUD_DIR / "acm_certificates.json"
    original = json.loads(filepath.read_text(encoding="utf-8"))

    signatures = [
        finding
        for finding in scan(filepath)
        if finding.crypto_function == CryptoFunction.SIGN
    ]

    for index, finding in enumerate(signatures):
        evidence = finding.evidence[0]

        assert evidence.file_path == str(filepath)
        assert evidence.json_path == (
            f"$.Certificates[{index}].SignatureAlgorithm"
        )
        assert evidence.rule_id == "AWS-ACM-SIGNATURE"
        assert json.loads(evidence.matched_snippet) == (
            original["Certificates"][index]
        )


@pytest.mark.parametrize(
    "certificate",
    [
        {},
        {"KeyAlgorithm": "FUTURE_KEY_ALGORITHM"},
    ],
)
def test_acm_unknown_public_key_parameters(certificate):
    findings = parse_acm_certificates(
        {"Certificates": [certificate]},
        Path("acm.json"),
    )

    assert len(findings) == 1

    finding = findings[0]
    assert finding.algorithm_name == certificate.get(
        "KeyAlgorithm", "unknown"
    )
    assert finding.asset_type == AssetType.CERTIFICATE
    assert finding.key_size is None
    assert finding.mode is None
    assert finding.oid is None


def test_acm_missing_signature_does_not_create_signature_finding():
    findings = parse_acm_certificates(
        {"Certificates": [{"KeyAlgorithm": "RSA_2048"}]},
        Path("acm.json"),
    )

    assert len(findings) == 1
    assert findings[0].asset_type == AssetType.CERTIFICATE
    assert findings[0].crypto_function == CryptoFunction.UNKNOWN


def test_acm_signature_without_public_key_parameters():
    findings = parse_acm_certificates(
        {"Certificates": [{"SignatureAlgorithm": "SHA256WITHRSA"}]},
        Path("acm.json"),
    )

    assert len(findings) == 2

    certificate, signature = findings

    assert certificate.algorithm_name == "unknown"
    assert certificate.key_size is None

    assert signature.algorithm_name == "SHA256WITHRSA"
    assert signature.crypto_function == CryptoFunction.SIGN
    assert signature.key_size is None


def test_acm_empty_inventory():
    assert parse_acm_certificates(
        {"Certificates": []},
        Path("acm.json"),
    ) == []


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"Certificates": None},
        {"Certificates": {}},
        {"Certificates": [42]},
    ],
)
def test_acm_invalid_inventory_shape(data):
    with pytest.raises(ValueError):
        parse_acm_certificates(data, Path("acm.json"))


@pytest.mark.parametrize("key_algorithm", ["", "   ", 2048, []])
def test_acm_invalid_key_algorithm(key_algorithm):
    with pytest.raises(ValueError, match="KeyAlgorithm"):
        parse_acm_certificates(
            {"Certificates": [{"KeyAlgorithm": key_algorithm}]},
            Path("acm.json"),
        )


@pytest.mark.parametrize("signature_algorithm", ["", "   ", 42, []])
def test_acm_invalid_signature_algorithm(signature_algorithm):
    with pytest.raises(ValueError, match="SignatureAlgorithm"):
        parse_acm_certificates(
            {
                "Certificates": [
                    {
                        "KeyAlgorithm": "RSA_2048",
                        "SignatureAlgorithm": signature_algorithm,
                    }
                ]
            },
            Path("acm.json"),
        )


def test_elb_listener_protocols():
    findings = [
        finding
        for finding in scan(CLOUD_DIR / "load_balancer_listeners.json")
        if finding.evidence[0].rule_id == "AWS-ELB-LISTENER-PROTOCOL"
    ]

    assert [finding.protocol for finding in findings] == [
        "HTTPS",
        "HTTP",
        "HTTPS",
        "HTTPS",
        "HTTPS",
        "TLS",
        "HTTP",
    ]

    for finding in findings:
        assert finding.algorithm_name == finding.protocol
        assert finding.asset_type == AssetType.PROTOCOL
        assert finding.observation == "configured"
        assert finding.key_size is None
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN


def test_elb_listener_evidence():
    filepath = CLOUD_DIR / "load_balancer_listeners.json"
    original = json.loads(filepath.read_text(encoding="utf-8"))
    findings = [
        finding
        for finding in scan(filepath)
        if finding.evidence[0].rule_id == "AWS-ELB-LISTENER-PROTOCOL"
    ]

    expected = [
        (
            f"$.LoadBalancers[{lb_index}].Listeners[{listener_index}]",
            listener,
        )
        for lb_index, load_balancer in enumerate(original["LoadBalancers"])
        for listener_index, listener in enumerate(load_balancer["Listeners"])
    ]

    assert len(findings) == len(expected)

    for finding, (location, listener) in zip(findings, expected):
        evidence = finding.evidence[0]

        assert evidence.file_path == str(filepath)
        assert evidence.json_path == location
        assert evidence.rule_id == "AWS-ELB-LISTENER-PROTOCOL"
        assert json.loads(evidence.matched_snippet) == listener


def test_elb_http_actions_are_preserved():
    findings = scan(CLOUD_DIR / "load_balancer_listeners.json")
    http_findings = [
        finding for finding in findings
        if finding.protocol == "HTTP"
    ]

    assert len(http_findings) == 2

    actions = [
        json.loads(finding.evidence[0].matched_snippet)["DefaultActions"][0]
        for finding in http_findings
    ]

    assert actions[0]["Type"] == "redirect"
    assert actions[0]["RedirectConfig"]["Protocol"] == "HTTPS"
    assert actions[1]["Type"] == "forward"


def test_elb_missing_protocol_is_unknown():
    listener = {
        "ListenerArn": "arn:example",
        "Port": 443,
    }

    findings = parse_load_balancers(
        {"LoadBalancers": [{"Listeners": [listener]}]},
        Path("elb.json"),
    )

    assert len(findings) == 1

    finding = findings[0]
    assert finding.algorithm_name == "unknown"
    assert finding.protocol is None
    assert finding.key_size is None
    assert json.loads(finding.evidence[0].matched_snippet) == listener


def test_elb_does_not_infer_protocol_from_port():
    findings = parse_load_balancers(
        {"LoadBalancers": [{"Listeners": [{"Port": 80}]}]},
        Path("elb.json"),
    )

    assert findings[0].protocol is None
    assert findings[0].algorithm_name == "unknown"


@pytest.mark.parametrize(
    "data",
    [
        {"LoadBalancers": []},
        {"LoadBalancers": [{"Listeners": []}]},
    ],
)
def test_elb_empty_inventory(data):
    assert parse_load_balancers(data, Path("elb.json")) == []


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"LoadBalancers": None},
        {"LoadBalancers": {}},
        {"LoadBalancers": [42]},
    ],
)
def test_elb_invalid_inventory_shape(data):
    with pytest.raises(ValueError):
        parse_load_balancers(data, Path("elb.json"))


@pytest.mark.parametrize(
    "load_balancer",
    [
        {},
        {"Listeners": None},
        {"Listeners": {}},
        {"Listeners": [42]},
    ],
)
def test_elb_invalid_listeners_shape(load_balancer):
    with pytest.raises(ValueError):
        parse_load_balancers(
            {"LoadBalancers": [load_balancer]},
            Path("elb.json"),
        )


@pytest.mark.parametrize("protocol", ["", "   ", 443, []])
def test_elb_invalid_protocol(protocol):
    with pytest.raises(ValueError, match="Protocol"):
        parse_load_balancers(
            {
                "LoadBalancers": [
                    {"Listeners": [{"Protocol": protocol}]}
                ]
            },
            Path("elb.json"),
        )


def test_load_elb_policy_map():
    policy_file = CLOUD_DIR.parents[1] / "data" / "elb_policies.json"
    policies = load_elb_policy_map(policy_file)

    policy = policies["ELBSecurityPolicy-FS-1-2-Res-2020-10"]

    assert policy["protocols"] == ["TLSv1.2"]
    assert policy["ciphers"] == [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ]
    assert policy["source_url"].startswith("https://docs.aws.amazon.com/")
    assert policies.get("UNKNOWN_POLICY") is None


@pytest.mark.parametrize(
    "field, value",
    [
        ("protocols", None),
        ("protocols", "TLSv1.2"),
        ("ciphers", []),
        ("ciphers", [42]),
    ],
)
def test_invalid_policy_capabilities(tmp_path, field, value):
    policy = {
        "protocols": ["TLSv1.2"],
        "ciphers": ["EXAMPLE-CIPHER"],
        "source_url": "https://example.com/policy",
    }
    policy[field] = value

    filepath = tmp_path / "policies.json"
    filepath.write_text(
        json.dumps({"policies": {"TEST-POLICY": policy}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=field):
        load_elb_policy_map(filepath)


def test_missing_policy_map(tmp_path):
    filepath = tmp_path / "policies.json"
    filepath.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="policies"):
        load_elb_policy_map(filepath)


def test_elb_policy_protocol_expansion():
    policy_file = CLOUD_DIR.parents[1] / "data" / "elb_policies.json"
    
    all_policies = load_elb_policy_map(policy_file)
    policy_name = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
    policy_map = {policy_name: all_policies[policy_name]}
    
    filepath = CLOUD_DIR / "load_balancer_listeners.json"

    findings = parse_load_balancers(
        json.loads(filepath.read_text(encoding="utf-8")),
        filepath,
        policy_map,
        policy_file,
    )

    expanded = [
        finding
        for finding in findings
        if any(
            evidence.rule_id == "AWS-ELB-POLICY-PROTOCOL"
            for evidence in finding.evidence
        )
    ]

    assert len(findings) == 16
    assert len(expanded) == 1

    finding = expanded[0]
    assert finding.protocol == "TLSv1.2"
    assert finding.observation == "configured"
    assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN

    assert finding.evidence[0].json_path == (
        "$.LoadBalancers[2].Listeners[0].SslPolicy"
    )
    assert finding.evidence[1].file_path == str(policy_file)
    assert json.loads(finding.evidence[1].matched_snippet) == (
        policy_map["ELBSecurityPolicy-FS-1-2-Res-2020-10"]
    )


def test_elb_unknown_policy_does_not_invent_tls_versions():
    data = {
        "LoadBalancers": [
            {
                "Listeners": [
                    {
                        "Protocol": "HTTPS",
                        "SslPolicy": "UNKNOWN_POLICY",
                    }
                ]
            }
        ]
    }

    findings = parse_load_balancers(
        data,
        Path("elb.json"),
        {},
        Path("policies.json"),
    )

    assert len(findings) == 2
    assert findings[0].protocol == "HTTPS"

    unknown = findings[1]
    assert unknown.algorithm_name == "unknown"
    assert unknown.protocol == "TLS"
    assert unknown.confidence == "low"
    assert unknown.key_size is None
    assert unknown.quantum_risk == QuantumRiskLevel.UNKNOWN
    assert unknown.classical_risk == QuantumRiskLevel.UNKNOWN
    assert unknown.evidence[0].rule_id == "AWS-ELB-POLICY-UNMAPPED"


def test_elb_policy_map_requires_evidence_filepath():
    with pytest.raises(ValueError, match="policy_file"):
        parse_load_balancers(
            {"LoadBalancers": []},
            Path("elb.json"),
            policy_map={},
        )


def test_elb_policy_cipher_expansion():
    policy_file = CLOUD_DIR.parents[1] / "data" / "elb_policies.json"
    
    all_policies = load_elb_policy_map(policy_file)
    policy_name = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
    policy_map = {policy_name: all_policies[policy_name]}
    
    filepath = CLOUD_DIR / "load_balancer_listeners.json"

    findings = parse_load_balancers(
        json.loads(filepath.read_text(encoding="utf-8")),
        filepath,
        policy_map,
        policy_file,
    )

    ciphers = [
        finding
        for finding in findings
        if any(
            evidence.rule_id == "AWS-ELB-POLICY-CIPHER"
            for evidence in finding.evidence
        )
    ]

    assert [finding.algorithm_name for finding in ciphers] == [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ]

    for finding in ciphers:
        assert finding.asset_type == AssetType.ALGORITHM
        assert finding.protocol == "TLS"
        assert finding.observation == "configured"
        assert finding.key_size is None
        assert finding.mode is None
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN


def test_elb_cipher_evidence():
    policy_file = CLOUD_DIR.parents[1] / "data" / "elb_policies.json"
    
    all_policies = load_elb_policy_map(policy_file)
    policy_name = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
    policy_map = {policy_name: all_policies[policy_name]}
    
    filepath = CLOUD_DIR / "load_balancer_listeners.json"

    findings = parse_load_balancers(
        json.loads(filepath.read_text(encoding="utf-8")),
        filepath,
        policy_map,
        policy_file,
    )

    ciphers = [
        finding
        for finding in findings
        if any(
            evidence.rule_id == "AWS-ELB-POLICY-CIPHER"
            for evidence in finding.evidence
        )
    ]

    assert len(ciphers) == 4

    for index, finding in enumerate(ciphers):
        assert len(finding.evidence) == 2
        assert finding.evidence[0].file_path == str(filepath)
        assert finding.evidence[0].json_path == (
            "$.LoadBalancers[2].Listeners[0].SslPolicy"
        )
        assert finding.evidence[1].file_path == str(policy_file)
        assert finding.evidence[1].json_path == (
            f"$.policies[{json.dumps(policy_name)}].ciphers[{index}]"
        )
        assert json.loads(finding.evidence[1].matched_snippet) == (
            policy_map[policy_name]
        )


def test_policy_map_covers_dataset():
    policy_file = CLOUD_DIR.parents[1] / "data" / "elb_policies.json"
    policy_map = load_elb_policy_map(policy_file)

    data = json.loads(
        (CLOUD_DIR / "load_balancer_listeners.json").read_text(
            encoding="utf-8"
        )
    )

    referenced_policies = {
        listener["SslPolicy"]
        for load_balancer in data["LoadBalancers"]
        for listener in load_balancer["Listeners"]
        if "SslPolicy" in listener
    }

    assert len(referenced_policies) == 5
    assert referenced_policies <= policy_map.keys()


def test_full_elb_policy_expansion():
    policy_file = CLOUD_DIR.parents[1] / "data" / "elb_policies.json"
    policy_map = load_elb_policy_map(policy_file)
    filepath = CLOUD_DIR / "load_balancer_listeners.json"

    findings = parse_load_balancers(
        json.loads(filepath.read_text(encoding="utf-8")),
        filepath,
        policy_map,
        policy_file,
    )

    protocols = [
        finding
        for finding in findings
        if any(
            evidence.rule_id == "AWS-ELB-POLICY-PROTOCOL"
            for evidence in finding.evidence
        )
    ]

    ciphers = [
        finding
        for finding in findings
        if any(
            evidence.rule_id == "AWS-ELB-POLICY-CIPHER"
            for evidence in finding.evidence
        )
    ]

    assert len(findings) == 79
    assert len(protocols) == 9
    assert len(ciphers) == 63

    assert [finding.protocol for finding in protocols] == [
        "TLSv1.2", "TLSv1.1", "TLSv1.0",
        "TLSv1.2", "TLSv1.1",
        "TLSv1.2",
        "TLSv1.3", "TLSv1.2",
        "TLSv1.2",
    ]

    for finding in protocols + ciphers:
        assert finding.observation == "configured"
        assert len(finding.evidence) == 2
        assert finding.quantum_risk == QuantumRiskLevel.UNKNOWN
        assert finding.classical_risk == QuantumRiskLevel.UNKNOWN


def test_scan_expands_elb_policies():
    findings = scan(CLOUD_DIR / "load_balancer_listeners.json")

    assert len(findings) == 79

    rule_counts = {
        "AWS-ELB-LISTENER-PROTOCOL": 0,
        "AWS-ELB-POLICY-PROTOCOL": 0,
        "AWS-ELB-POLICY-CIPHER": 0,
    }

    for finding in findings:
        for evidence in finding.evidence:
            if evidence.rule_id in rule_counts:
                rule_counts[evidence.rule_id] += 1

    assert rule_counts == {
        "AWS-ELB-LISTENER-PROTOCOL": 7,
        "AWS-ELB-POLICY-PROTOCOL": 9,
        "AWS-ELB-POLICY-CIPHER": 63,
    }


def test_scan_finds_policy_map_from_another_directory(tmp_path, monkeypatch):
    filepath = CLOUD_DIR / "load_balancer_listeners.json"

    monkeypatch.chdir(tmp_path)

    findings = scan(filepath)

    assert len(findings) == 79
    assert any(
        finding.protocol == "TLSv1.3"
        for finding in findings
    )


def test_scan_cloud_directory():
    findings = scan(CLOUD_DIR)

    assert len(findings) == 99

    assert sum(
        finding.asset_type == AssetType.KEY
        for finding in findings
    ) == 10

    assert sum(
        finding.asset_type == AssetType.CERTIFICATE
        for finding in findings
    ) == 5

    assert sum(
        finding.asset_type == AssetType.ALGORITHM
        for finding in findings
    ) == 68

    assert sum(
        finding.asset_type == AssetType.PROTOCOL
        for finding in findings
    ) == 16


def test_scan_empty_directory(tmp_path):
    assert scan(tmp_path) == []


def test_scan_directory_includes_nested_exports(tmp_path):
    nested = tmp_path / "exports"
    nested.mkdir()

    filepath = nested / "kms.json"
    filepath.write_text(
        json.dumps({"Keys": [{"KeySpec": "RSA_2048"}]}),
        encoding="utf-8",
    )

    findings = scan(tmp_path)

    assert len(findings) == 1
    assert findings[0].algorithm_name == "RSA"
    assert findings[0].evidence[0].file_path == str(filepath)


def test_scan_directory_rejects_corrupt_json(tmp_path):
    filepath = tmp_path / "broken.json"
    filepath.write_text('{"Keys": [', encoding="utf-8")

    with pytest.raises(ValueError, match="JSON inválido"):
        scan(tmp_path)


def test_scan_directory_rejects_unsupported_export(tmp_path):
    filepath = tmp_path / "other.json"
    filepath.write_text('{"OtherResources": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="ainda não suportado"):
        scan(tmp_path)


def test_elb_missing_policy_is_explicit():
    listener = {"Protocol": "HTTPS", "Port": 443}

    findings = parse_load_balancers(
        {"LoadBalancers": [{"Listeners": [listener]}]},
        Path("elb.json"),
        {},
        Path("policies.json"),
    )

    assert len(findings) == 2

    unknown = findings[1]
    assert unknown.algorithm_name == "unknown"
    assert unknown.confidence == "low"
    assert unknown.evidence[0].rule_id == "AWS-ELB-POLICY-MISSING"
    assert unknown.evidence[0].json_path == (
        "$.LoadBalancers[0].Listeners[0]"
    )
    assert json.loads(unknown.evidence[0].matched_snippet) == listener


@pytest.mark.parametrize("policy_name", ["", "   ", 42, []])
def test_elb_invalid_policy_name(policy_name):
    with pytest.raises(ValueError, match="SslPolicy"):
        parse_load_balancers(
            {
                "LoadBalancers": [
                    {
                        "Listeners": [
                            {
                                "Protocol": "HTTPS",
                                "SslPolicy": policy_name,
                            }
                        ]
                    }
                ]
            },
            Path("elb.json"),
            {},
            Path("policies.json"),
        )


def test_cloud_listener_certificate_references():
    findings = scan(CLOUD_DIR)

    certificates = {}

    for finding in findings:
        if finding.asset_type == AssetType.CERTIFICATE:
            resource = json.loads(finding.evidence[0].matched_snippet)
            certificates[resource["CertificateArn"]] = resource

    listeners = [
        json.loads(finding.evidence[0].matched_snippet)
        for finding in findings
        if finding.evidence[0].rule_id == "AWS-ELB-LISTENER-PROTOCOL"
    ]

    assert len(certificates) == 5
    assert len(listeners) == 7

    reference_count = 0

    for listener in listeners:
        for reference in listener.get("Certificates", []):
            certificate_arn = reference["CertificateArn"]

            assert certificate_arn in certificates

            certificate = certificates[certificate_arn]
            assert listener["ListenerArn"] in certificate["InUseBy"]

            reference_count += 1

    assert reference_count == 5
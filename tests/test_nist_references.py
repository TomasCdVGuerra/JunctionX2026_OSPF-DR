"""Contextual references, including negative cases and round-trip presentation."""
import pytest

from dashboard import _build_cbom_from_findings, load_findings_dataframe
from scanner.models import CryptoFinding, CryptoFunction, Evidence
from scanner.nist_references import (
    collect_nist_references,
    nist_references_for_algorithm,
)
from scanner.risk import enrich_finding


@pytest.mark.parametrize("name,operation,mode,expected", [
    ("AES-256-GCM", "encrypt", None, ["FIPS 197", "SP 800-38D"]),
    ("AES", "encrypt", "CBC", ["FIPS 197", "SP 800-38A"]),
    ("RSA-2048", "sign", None, ["SP 800-131A Rev. 2", "FIPS 186-5"]),
    ("RSA", "unknown", None, ["SP 800-131A Rev. 2"]),
    ("RSA", "key_exchange", None, ["SP 800-131A Rev. 2", "SP 800-56B Rev. 2"]),
    ("SHA256WITHRSA", "unknown", None, ["SP 800-131A Rev. 2", "FIPS 186-5", "FIPS 180-4"]),
    ("ECDHE", "key_exchange", None, ["SP 800-56A Rev. 3"]),
    ("TLSv1.2", "unknown", None, ["SP 800-52 Rev. 2"]),
    ("ML-KEM-768", "key_exchange", None, ["FIPS 203"]),
    ("SM4", "encrypt", None, []),
    ("ChaCha20-Poly1305", "encrypt", None, []),
    ("X25519", "key_exchange", None, []),
    ("MadeUpSHA256", "digest", None, []),
])
def test_contextual_references(name, operation, mode, expected):
    assert nist_references_for_algorithm(name, CryptoFunction(operation), mode) == expected


def test_tls_suite_references_components_without_claiming_full_assessment():
    references = nist_references_for_algorithm("TLS_AES_256_GCM_SHA384")
    assert references == ["SP 800-52 Rev. 2", "FIPS 197", "SP 800-38D", "FIPS 180-4"]
    original = CryptoFinding(
        algorithm_name="TLS_AES_256_GCM_SHA384", source_type="cloud-posture",
        observation="advertised", evidence=[Evidence(file_path="elb.json", rule_id="ELB")],
    )
    enriched = enrich_finding(original)
    assert enriched.quantum_risk.value == "unknown"
    assert original.evidence[0].nist_standard is None
    for representation in ([enriched], _build_cbom_from_findings([original])):
        row = load_findings_dataframe(representation).iloc[0]
        assert row["NIST References"] == "; ".join(references)


def test_aggregate_original_and_engine_references_without_duplicates():
    assert collect_nist_references([
        {"nist_standard": "FIPS 197"}, {"nist_standard": "none"},
        {"nist_standard": "FIPS 197; SP 800-38D"},
    ]) == "FIPS 197; SP 800-38D"


@pytest.mark.parametrize("name,expected", [
    ("ECDHE-secp256r1", ["SP 800-56A Rev. 3", "SP 800-186"]),
    ("DHE-ffdhe2048", ["SP 800-56A Rev. 3"]),
    ("DHE", ["SP 800-56A Rev. 3"]),
    ("HKDF-SHA-256", ["SP 800-56C Rev. 2", "FIPS 180-4"]),
    ("TLS-PRF-SHA-384", ["SP 800-135 Rev. 1", "SP 800-52 Rev. 2", "FIPS 180-4"]),
    ("X25519MLKEM768", ["FIPS 203 (ML-KEM component)"]),
    ("3DES", ["SP 800-131A Rev. 2"]),
    ("ECDHE-unrecognised", []),
    ("HKDF-MadeUp", []),
    ("X25519Kyber768Draft00", []),
    ("ECDHE-X25519", []),
])
def test_network_names_have_scoped_references(name, expected):
    assert nist_references_for_algorithm(name) == expected

# Purpose:
# Ground-truth test suite comparing scanner outputs against hand-checked expected findings for zero false positives and zero false negatives.
#
# Responsibilities:
# - Load expected findings fixture from tests/fixtures/expected_findings.json for every sample file across cloud, Python, Java, and Go.
# - Execute scanner pipeline against challenge material and compare actual findings with ground-truth expectation.
# - Fail test runs on any missing expected finding (false negative) or unexpected phantom finding (false positive).
# - Assert that risk levels strictly match cryptographic reality (e.g. classical symmetric is never marked Critical, quantum-broken asymmetric is always marked Critical).
#
# Planned interface:
# - load_expected_findings() -> list[dict]: reads and deserializes tests/fixtures/expected_findings.json.
# - test_ground_truth_source_python(): verifies findings against python/ sample scripts.
# - test_ground_truth_source_java(): verifies findings against java/ sample classes.
# - test_ground_truth_source_go(): verifies findings against go/ microservice packages.
# - test_ground_truth_cloud(): verifies findings against cloud-posture JSON fixtures.
# - assert_findings_match(actual: list[CryptoFinding], expected: list[dict]) -> None: performs bidirectional equality assertion.
#
# Rules and edge cases:
# - Failing conditions: Must fail on missing findings AND on false positives.
# - Negative risk assertions (MUST NOT be Critical): HMAC-SHA256, SHA-256, SHA-384, and PBKDF2 must NEVER be classified as Critical (they are symmetric / quantum-resistant).
# - Positive risk assertions (MUST be Critical): RSA of any key size, Ed25519, and ECDSA/ECDH on P-256 or P-384 must ALWAYS be classified as Critical (vulnerable to Shor's algorithm).
# - Insecure symmetric modes (AES-ECB) and broken hashes (MD5, SHA-1) must also be classified as Critical due to classical breaks.
#
# Scoring link:
# - Accuracy (40%): Guarantees precision by enforcing zero false positives and zero false negatives against verified test fixtures.
# - Coverage (25%): Validates comprehensive detection across all three languages and cloud posture exports.

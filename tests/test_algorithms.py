# Purpose:
# Test suite for algorithm string normalization, OID resolution, and post-quantum risk classification logic.
#
# Responsibilities:
# - Validate normalization across uppercase, lowercase, punctuation, and hyphen variations (e.g. "sha256", "SHA-256").
# - Assert that standard OID mappings match authoritative NIST and PKCS specifications (e.g. SHA-256, RSA, Ed25519).
# - Test quantum risk classification rules: verify RSA (any size) and Ed25519 are classified as Critical, AES-128 as Medium, and AES-256 as Safe.
# - Confirm that unresolvable algorithms safely return "unknown" rather than speculative guesses.
#
# Planned interface:
# - test_normalise_variations(): tests case and separator normalization.
# - test_oid_mappings(): asserts correct standard OID strings for known algorithms.
# - test_risk_classification(): verifies risk tiers and security bit calculations.
# - test_unknown_algorithm_handling(): asserts "unknown" fallback on novel or unparseable names.
#
# Rules and edge cases:
# - Composite algorithms like "SHA1withRSA" must resolve both the digest vulnerability and asymmetric Shor risk.
# - Ensure OID lookup returns "unknown" when passed an unsupported string.
#
# Scoring link:
# - Accuracy (40%): Enforces rigorous cryptographic correctness for algorithm names and threat classifications.
# - Standardisation and traceability (20%): Verifies proper mapping to official OIDs and NIST standards.

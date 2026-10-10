# Purpose:
# Test suite verifying AWS cloud posture JSON scanning and policy expansion against sample fixtures.
#
# Responsibilities:
# - Test ingestion of KMS key inventory (kms_key_inventory.json), asserting correct key specs and usages are detected.
# - Test load balancer listener parsing (load_balancer_listeners.json) combined with data/elb_policies.json policy expansion.
# - Test ACM certificate inventory parsing (acm_certificates.json), validating signature algorithms and domain evidence.
# - Verify that findings contain full evidence chains: JSON file path, resource ARN, rule ID, and risk reasoning.
#
# Planned interface:
# - test_parse_kms_inventory(): asserts extraction of RSA and symmetric KMS keys.
# - test_parse_elb_listeners_with_policy_expansion(): asserts TLS cipher expansion from SslPolicy names.
# - test_parse_acm_certificates(): asserts detection of certificate algorithms and expiration dates.
#
# Rules and edge cases:
# - Policy expansion test must confirm that cipher suites are derived from data/elb_policies.json rather than hardcoded assumptions.
# - Verify that cleartext HTTP listeners (port 80) generate an unencrypted protocol warning finding.
#
# Scoring link:
# - Coverage (25%): Validates cloud infrastructure cryptographic inventory capabilities.
# - Accuracy (40%): Verifies proper expansion of high-level AWS policy names into underlying cryptographic primitives.

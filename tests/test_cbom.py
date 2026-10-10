# Purpose:
# Test suite for CycloneDX 1.6 Cryptography Bill of Materials (CBOM) serialization and JSON schema validation.
#
# Responsibilities:
# - Validate the generated CBOM document strictly against the official CycloneDX 1.6 JSON schema specification using the jsonschema library.
# - Ensure test validation operates completely offline by referencing local schema files and dependencies stored in tests/fixtures/.
# - Validate that cryptoProperties, algorithmProperties, classicalSecurityLevel, nistQuantumSecurityLevel, OIDs, and evidence blocks adhere to schema types and constraints.
# - Confirm that field name checks alone are rejected as insufficient and full structural validation is executed.
#
# Planned interface:
# - test_cbom_against_official_cyclonedx_schema(): loads tests/fixtures/bom-1.6.schema.json, executes jsonschema.validate(), and verifies strict compliance.
# - test_cbom_offline_self_contained(): verifies no external network calls are made during schema resolution and reference checking.
# - test_cbom_evidence_fields_present(): verifies that file paths, line numbers, snippets, and rule IDs are formatted properly inside evidence.occurrences.
#
# Rules and edge cases:
# - Checking field names alone is NOT enough; the full document MUST validate against the official CycloneDX 1.6 JSON schema using jsonschema.validate().
# - All referenced sub-schemas (e.g., spdx.schema.json, jsf-0.82.schema.json) must reside locally in tests/fixtures/ so the test suite passes in air-gapped/offline environments.
# - If an attribute is "unknown", verify that the schema allows or accommodates the field without schema validation failures.
#
# Scoring link:
# - Standardisation and traceability (20%): Proves compliance with the official CycloneDX 1.6 industry specification.
# - Accuracy (40%): Guarantees that exported artifacts are syntactically and semantically valid for external CBOM consumers.

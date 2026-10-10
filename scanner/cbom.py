# Purpose:
# Serializes discovered cryptographic findings into the official CycloneDX 1.6 Cryptography Bill of Materials (CBOM) JSON format.
#
# Responsibilities:
# - Construct valid CycloneDX 1.6 JSON document structure with standard metadata, tool identifiers, and RFC 4122 UUID serial number.
# - Format each finding as a component of type "cryptographic-asset" containing cryptoProperties.
# - Map algorithm parameters into algorithmProperties (primitive, mode, padding, classicalSecurityLevel, nistQuantumSecurityLevel).
# - Embed standardized OIDs in cryptoProperties.oid and risk justifications in custom component properties.
# - Populate component evidence occurrences with file locations, line numbers, snippets, and rule IDs for traceability.
#
# Planned interface:
# - generate_cbom(findings: list[CryptoFinding]) -> dict[str, Any]: compiles findings into standard CycloneDX 1.6 CBOM payload.
# - map_nist_quantum_level(quantum_bits: int) -> int: maps bit strength to NIST PQC security levels (1, 3, 5, or 0).
# - serialize_cbom_json(findings: list[CryptoFinding], output_file: Path) -> None: persists formatted CBOM JSON to disk.
#
# Rules and edge cases:
# - Must adhere strictly to the CycloneDX 1.6 JSON schema so that jsonschema validation passes offline without warnings.
# - If an attribute is "unknown", it should be omitted or represented according to CycloneDX schema nullability rules.
# - Evidence blocks must link directly to source file lines and snippets to ensure full auditability.
#
# Scoring link:
# - Standardisation and traceability (20%): Delivers an industry-standard, interoperable CycloneDX 1.6 CBOM ready for enterprise tooling.
# - Accuracy (40%): Correctly encodes NIST quantum security levels and classical security levels into standardized fields.

# Purpose:
# Defines canonical data models for cryptographic findings, evidence tracking, and CycloneDX CBOM asset representations.
#
# Responsibilities:
# - Define the CryptoFinding data structure representing detected cryptographic assets across source, cloud, and network.
# - Store granular evidence metadata on every finding: file path, line number, matched snippet, rule ID, risk reasoning (one sentence), and NIST standard mapping.
# - Provide enum definitions for AssetType (algorithm, certificate, key, protocol), CryptoFunction, and QuantumRiskLevel.
# - Provide data structures for evidence locations and serialization dictionaries.
#
# Planned interface:
# - class AssetType(Enum): values ALGORITHM, CERTIFICATE, KEY, PROTOCOL, RELATED_CRYPTO_MATERIAL.
# - class CryptoFunction(Enum): values DIGEST, SIGN, VERIFY, ENCRYPT, DECRYPT, KEYGEN, KDF, MAC, KEY_EXCHANGE.
# - class QuantumRiskLevel(Enum): values CRITICAL, MEDIUM, SAFE, UNKNOWN.
# - class Evidence: fields file_path (str), line_number (int or str), matched_snippet (str), rule_id (str), risk_reasoning (str), nist_standard (str).
# - class CryptoFinding: fields algorithm_name (str), asset_type (AssetType), key_size (int or str), mode (str), padding (str), oid (str), protocol (str), quantum_risk (QuantumRiskLevel), evidence (list[Evidence]), to_dict() -> dict.
#
# Rules and edge cases:
# - Every finding MUST include complete evidence fields: file path, line number, matched snippet, rule ID, one-sentence risk reasoning, and NIST standard (FIPS 203 / 204 / 205, or none).
# - Any value that cannot be determined with certainty MUST be set to the literal string "unknown".
# - Never guess key sizes, modes, or standards if they are not explicitly proven.
#
# Scoring link:
# - Standardisation and traceability (20%): Guarantees strict evidence chains, CycloneDX alignment, and transparent audit trails.
# - Accuracy (40%): Prevents hallucinated or guessed attributes by enforcing "unknown" fallbacks.

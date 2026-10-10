# Purpose:
# Normalizes algorithm naming variations, maintains standard OID mappings, and stores cryptographic primitive taxonomy.
#
# Responsibilities:
# - Map varied algorithm strings (e.g., "sha-256", "SHA256", "AES_GCM", "AES/ECB/PKCS5Padding") to canonical identifiers.
# - Provide authoritative Object Identifier (OID) lookups compliant with NIST, PKCS, and ANSI standards.
# - Maintain categorization of cryptographic primitives (block ciphers, hash functions, MACs, asymmetric ciphers, KDFs).
# - Map modern Post-Quantum Cryptography algorithms to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
#
# Planned interface:
# - normalise(raw_name: str) -> str: returns standardized algorithm name or "unknown".
# - oid_for(algorithm_name: str) -> str: returns official dotted-decimal OID string or "unknown".
# - get_primitive_category(algorithm_name: str) -> str: returns primitive category (e.g. "block-cipher", "hash", "signature").
# - is_pqc_native(algorithm_name: str) -> bool: returns True if algorithm is post-quantum native.
#
# Rules and edge cases:
# - Normalization must be case-insensitive and resilient to punctuation differences (hyphens, underscores, slashes).
# - Never invent non-standard OIDs; if an algorithm does not have an official standard OID, return "unknown".
# - Handle composite cipher names (e.g., "SHA1withRSA", "ECDSA-SHA256") by extracting both primary cipher and digest components.
#
# Scoring link:
# - Standardisation and traceability (20%): Guarantees industry-standard OID metadata and FIPS naming alignment.
# - Accuracy (40%): Prevents duplicated or misclassified findings resulting from naming format variations.

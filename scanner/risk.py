# Purpose:
# Evaluates cryptographic findings against classical vulnerabilities and post-quantum threat models (Shor's and Grover's algorithms).
#
# Responsibilities:
# - Classify findings into risk tiers: Critical, Medium, Safe, or Unknown.
# - Evaluate classical breaks: mark MD5, SHA-1, DES, and AES-ECB mode as Critical due to existing classical compromise.
# - Evaluate Shor's algorithm impact: mark all integer factorization and discrete-log asymmetric schemes (RSA of any size, Ed25519, ECDSA, ECDH) as Critical.
# - Evaluate Grover's algorithm impact: mark symmetric ciphers with effective quantum strength below 128 bits (e.g. AES-128 halved to 64 bits) as Medium.
# - Classify quantum-resistant primitives: mark AES-256, SHA-384, SHA-512, and NIST FIPS 203/204/205 PQC standards as Safe.
# - Produce a concise, single-sentence risk reasoning explaining the verdict for every finding.
#
# Planned interface:
# - evaluate_risk(algorithm_name: str, key_size: str, mode: str) -> tuple[QuantumRiskLevel, int, int, str]: returns (risk_tier, classical_bits, quantum_bits, reasoning_sentence).
# - map_nist_standard(algorithm_name: str) -> str: returns "FIPS 203", "FIPS 204", "FIPS 205", or "none".
# - enrich_finding_risk(finding: CryptoFinding) -> None: mutates finding with risk evaluation and evidence reasoning.
#
# Rules and edge cases:
# - RSA is vulnerable to Shor's algorithm regardless of key size (1024, 2048, 4096 all fall to polynomial-time factoring), so ALL RSA instances MUST be classified as Critical.
# - Ed25519 and ECDSA curves (P-256, P-384) provide strong classical security but 0 quantum bits against Shor's algorithm, so they MUST be classified as Critical.
# - Symmetric HMAC-SHA256, SHA-256, SHA-384, and PBKDF2 MUST NOT be classified as Critical (they maintain quantum resistance against Grover's algorithm).
# - If key size or parameters are "unknown", assign risk based on algorithm family and state unknown in the reasoning.
#
# Scoring link:
# - Accuracy (40%): Enforces scientifically rigorous quantum risk models based on NIST Post-Quantum Cryptography transition guidance.
# - Standardisation and traceability (20%): Provides clear one-sentence justifications and NIST FIPS mappings for every asset.

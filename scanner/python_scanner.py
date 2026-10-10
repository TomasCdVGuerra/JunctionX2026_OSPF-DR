# Purpose:
# Python-specific static analysis scanner detecting cryptographic primitives in hashlib, hmac, and cryptography libraries.
#
# Responsibilities:
# - Detect calls to hashlib (md5, sha1, sha256, sha384, sha512), hmac, and the cryptography library (ciphers, asymmetric, kdf).
# - Resolve Python module-level constants (e.g., KEY_LEN = 32, EXPORT_KEY = b"0123456789ABCDEF") to extract accurate key sizes.
# - Calculate key sizes from hardcoded key byte lengths (e.g. len(EXPORT_KEY) == 16 implies AES-128).
# - Accurately differentiate quantum-vulnerable primitives (RSA, Ed25519) from quantum-safe/resistant symmetric algorithms (AES-256, SHA-384).
# - Capture exact line numbers, code snippets, rule IDs, and NIST standard references for evidence.
#
# Planned interface:
# - PYTHON_RULES: list of SourcePatternRule instances for Python cryptographic libraries.
# - resolve_python_constant(source_text: str, const_name: str) -> str: parses module-level assignments, returning value or "unknown".
# - scan_python_file(filepath: Path, base_dir: Path) -> list[CryptoFinding].
#
# Rules and edge cases:
# - If key size is passed as a variable (e.g. length=KEY_LEN), inspect same-file assignments to resolve its integer value.
# - If an inline byte literal or constant string key is used, calculate bits as len(raw_bytes) * 8 (e.g. 16 bytes -> 128 bits).
# - If a constant cannot be found or resolved, set key size to "unknown".
# - Ed25519 in webhook signatures must be flagged as Critical (quantum vulnerable) despite high classical security.
# - PBKDF2HMAC with SHA-256 is quantum-resistant and must not be marked Critical.
#
# Scoring link:
# - Accuracy (40%): Correctly extracts key sizes via constant resolution and attributes exact risk reasons.
# - Coverage (25%): Covers both Python standard library hashlib/hmac and modern third-party cryptography Hazmat APIs.

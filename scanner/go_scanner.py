# Purpose:
# Go-specific static analysis scanner detecting cryptographic primitives in standard library crypto/* packages and custom constructs.
#
# Responsibilities:
# - Detect usage of crypto/md5, crypto/sha1, crypto/sha256, crypto/sha512, crypto/aes, crypto/cipher, crypto/rsa, crypto/ed25519, and crypto/hmac.
# - Resolve same-file Go constants (e.g., const keyLen = 32, const iterations = 600_000, var exportKey = []byte("0123456789ABCDEF")).
# - Infer key sizes from byte slices or strings (e.g., 16-byte exportKey implies 128-bit key size).
# - Detect custom/hand-written PBKDF2 implementations built upon HMAC (such as in auth-gateway/main.go) and ensure they are captured.
# - Attach full evidence trails: file path, line number, matched snippet, rule ID, risk reasoning, and NIST mapping.
#
# Planned interface:
# - GO_RULES: list of SourcePatternRule instances for Go crypto primitives.
# - resolve_go_constant(source_text: str, const_name: str) -> str: parses const and var blocks, returning value or "unknown".
# - detect_custom_kdf(source_text: str, filepath: Path) -> list[CryptoFinding]: recognizes hand-written PBKDF2 loops using HMAC-SHA256.
# - scan_go_file(filepath: Path, base_dir: Path) -> list[CryptoFinding].
#
# Rules and edge cases:
# - Hand-written PBKDF2 built from HMAC-SHA256 (as seen in auth-gateway/main.go) MUST NOT be missed, and MUST NOT be classified as Critical (it is symmetric/quantum-resistant).
# - When key generation functions make slices with keyLen (e.g., make([]byte, keyLen)), resolve the const declaration (keyLen = 32 -> 256 bits).
# - Fallback to "unknown" if a constant identifier cannot be resolved in the same file.
# - Ed25519 (e.g. in agent-enrollment) and RSA (e.g. in invoice-service) MUST be classified as Critical (quantum vulnerable).
#
# Scoring link:
# - Accuracy (40%): Accurately detects custom KDF implementations without false Critical alarms, and resolves same-file constants.
# - Coverage (25%): Covers all Go crypto subpackages across microservices.

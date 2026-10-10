# Purpose:
# Java-specific static analysis scanner detecting cryptographic primitives in Java Cryptography Architecture (JCA/JCE).
#
# Responsibilities:
# - Detect calls to MessageDigest, Mac, Cipher, KeyPairGenerator, Signature, and SecretKeyFactory.
# - Resolve same-file static final constants (e.g., static final int KEY_BITS = 256, static final byte[] EXPORT_KEY = "...".getBytes()).
# - Infer key sizes from hardcoded byte arrays and string lengths (e.g. 16-character string literal equals 128-bit key).
# - Dissect transformation strings (e.g., "AES/ECB/PKCS5Padding" -> algorithm AES, mode ECB, padding PKCS5Padding).
# - Accurately flag insecure modes (ECB as Critical) and quantum-vulnerable signatures (RSA, Ed25519 as Critical).
#
# Planned interface:
# - JAVA_RULES: list of SourcePatternRule instances for JCA/JCE APIs.
# - resolve_java_constant(source_text: str, const_name: str) -> str: parses static final field definitions, returning value or "unknown".
# - scan_java_file(filepath: Path, base_dir: Path) -> list[CryptoFinding].
#
# Rules and edge cases:
# - When KeyGenerator.init() or KeyPairGenerator.initialize() receives a variable name (e.g. KEY_BITS), resolve its static final value.
# - If transformation string is stored in a constant (e.g., TRANSFORMATION), resolve it prior to parsing mode and padding.
# - If constant resolution fails, output "unknown" without speculative defaults.
# - PBKDF2WithHmacSHA256 must be classified as safe/resistant, never Critical.
#
# Scoring link:
# - Accuracy (40%): Identifies ECB mode vulnerabilities and correctly extracts algorithm parameters through constant resolution.
# - Coverage (25%): Covers full standard JCA/JCE class patterns including KeyPairGenerator, Cipher, and MessageDigest.

# Purpose:
# Base multi-language static analysis engine coordinating pattern matching, same-file constant resolution, and evidence capture.
#
# Responsibilities:
# - Orchestrate recursive source file discovery across repository paths for Python, Java, and Go files.
# - Dispatch target files to language-specific scanners and collect cryptographic findings.
# - Implement same-file constant resolution to infer key sizes, iterations, and modes when values are not inline literals.
# - Resolve key lengths from hardcoded string or byte literals (e.g., a 16-byte key string implies AES-128, 32-byte implies AES-256).
# - Fallback to "unknown" whenever a constant or property cannot be statically determined within the file.
# - Ensure line numbers, matching code snippets, and specific rule IDs are attached to each finding's evidence trail.
#
# Planned interface:
# - class SourcePatternRule: fields rule_id (str), pattern (regex), algorithm_name (str), default_key_size (str), risk_reasoning (str), nist_standard (str).
# - resolve_constant(file_content: str, variable_name: str) -> str: returns resolved value or "unknown".
# - infer_key_size_from_literal(literal_value: str) -> str: calculates key size from byte/string length (e.g., 16 bytes -> 128) or "unknown".
# - scan_file(file_path: Path, rules: list[SourcePatternRule], base_dir: Path) -> list[CryptoFinding].
# - scan_source_directory(directory_path: Path, base_dir: Path) -> list[CryptoFinding].
#
# Rules and edge cases:
# - Constant resolution: When key size is not a literal at the call site, resolve simple same-file constants (e.g., Java static final int, Go const, Python module-level constants).
# - Literal key inspection: If a raw key literal is defined (e.g. "0123456789ABCDEF"), determine key size from its byte length (16 bytes = 128 bits).
# - Unknown fallback: If key size cannot be reliably resolved from same-file context, record "unknown"; never make speculative guesses.
# - Custom implementations: Custom algorithms such as hand-written PBKDF2 built from HMAC (observed in Go) must not be missed and must not be misclassified as Critical.
#
# Scoring link:
# - Accuracy (40%): Precise constant resolution prevents missing parameters or classifying valid keys as generic.
# - Coverage (25%): Detects cryptographic operations across all supported programming languages and custom KDF constructs.

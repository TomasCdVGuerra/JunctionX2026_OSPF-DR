# Purpose:
# Test suite for multi-language static analysis pattern matching, constant resolution, and evidence tracking.
#
# Responsibilities:
# - Test Python crypto rule detection (hashlib, hmac, cryptography Hazmat primitives).
# - Test Java JCA/JCE rule detection (MessageDigest, Cipher, KeyPairGenerator, Signature).
# - Test Go crypto rule detection (crypto/md5, crypto/sha256, crypto/aes, crypto/ed25519, crypto/rsa).
# - Validate same-file constant resolution: confirm that key sizes defined in separate constants (e.g. KEY_BITS = 256, keyLen = 32) are resolved correctly.
# - Validate literal key inference: confirm that a hardcoded 16-byte key string resolves to AES-128.
# - Assert that evidence blocks capture accurate line numbers, matching code snippets, and rule IDs.
#
# Planned interface:
# - test_python_scanner_rules(): asserts findings against python sample files.
# - test_java_scanner_rules(): asserts findings against java sample files.
# - test_go_scanner_rules(): asserts findings against go sample microservices.
# - test_same_file_constant_resolution(): tests resolution of variables to integer bit lengths across all three languages.
# - test_custom_pbkdf2_detection_in_go(): ensures hand-written PBKDF2 in Go is identified and not marked Critical.
#
# Rules and edge cases:
# - Verify that when a constant cannot be resolved within the file, the scanner reports "unknown" instead of failing or guessing.
# - Verify that hand-written PBKDF2 built from HMAC-SHA256 in Go is detected and classified as Safe/Resistant, never Critical.
#
# Scoring link:
# - Accuracy (40%): Confirms precision in resolving constants and prevents inaccurate key size reports.
# - Coverage (25%): Verifies pattern coverage across Python, Java, and Go implementations.

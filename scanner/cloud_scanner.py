# Purpose:
# Parses AWS cloud posture JSON exports (KMS keys, ALB listeners, ACM certificates) and extracts cryptographic configurations.
#
# Responsibilities:
# - Parse AWS KMS key inventory JSON: extract KeySpec (RSA_2048, ECC_NIST_P256, SYMMETRIC_DEFAULT), KeyUsage, KeyState, and KeyArn.
# - Parse AWS Elastic Load Balancer listener configurations: map listener SslPolicy names to specific TLS protocols and cipher suites using data/elb_policies.json.
# - Parse AWS Certificate Manager (ACM) certificate inventory: extract KeyAlgorithm, SignatureAlgorithm, DomainName, and validity dates.
# - Produce CryptoFinding assets with complete evidence trails (JSON file path, key ARN/listener ARN as location, rule ID, and risk reasoning).
#
# Planned interface:
# - load_elb_policy_map(policy_file: Path) -> dict[str, Any]: loads data/elb_policies.json mapping policy names to ciphers and TLS versions.
# - parse_kms_keys(json_data: dict, filepath: Path) -> list[CryptoFinding].
# - parse_load_balancers(json_data: dict, filepath: Path, policy_map: dict) -> list[CryptoFinding].
# - parse_acm_certificates(json_data: dict, filepath: Path) -> list[CryptoFinding].
# - scan_json_file(filepath: Path, policy_map: dict) -> list[CryptoFinding].
# - scan_cloud_directory(directory_path: Path) -> list[CryptoFinding].
#
# Rules and edge cases:
# - Cloud posture JSON files contain only AWS SslPolicy names (e.g. ELBSecurityPolicy-2016-08); they do not contain raw cipher names, so data/elb_policies.json MUST be used for expansion.
# - If an unrecognized SslPolicy is encountered that cannot be mapped, record "unknown" for ciphers rather than guessing.
# - Inactive or disabled KMS keys must still be inventoried but have their status noted in evidence metadata.
# - Plaintext HTTP listeners (port 80) must be recorded with cleartext protocol warnings.
#
# Scoring link:
# - Coverage (25%): Ingests cloud infrastructure exports covering KMS encryption keys, load balancer termination, and TLS certificates.
# - Accuracy (40%): Correctly expands AWS security policies into underlying cipher suites using verified AWS reference tables.

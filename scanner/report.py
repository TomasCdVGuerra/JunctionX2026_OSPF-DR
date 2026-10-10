# Purpose:
# Computes aggregate security metrics, overall Quantum Risk Score, and statistical summaries for reporting and UI display.
#
# Responsibilities:
# - Calculate summary counts partitioned by risk tiers: Critical, Medium, Safe, and Unknown.
# - Calculate a normalized overall Quantum Risk Score (0 to 100 or 0 to 10) representing the organization's quantum exposure.
# - Weight findings based on risk severity: Critical findings (e.g. weight 10 or 1.0) contribute maximum penalty; Medium findings (e.g. weight 3 or 0.3) contribute moderate penalty; Safe findings (weight 0) contribute no penalty.
# - Generate structured report dictionaries consumable by both the Rich terminal reporter and the Streamlit dashboard.
#
# Planned interface:
# - calculate_quantum_risk_score(findings: list[CryptoFinding]) -> float: returns weighted aggregate score (e.g. 0-100 scale, where higher indicates higher quantum vulnerability).
# - generate_summary_counts(findings: list[CryptoFinding]) -> dict[str, int]: returns count mapping for Critical, Medium, Safe, and Total findings.
# - build_report_summary(findings: list[CryptoFinding]) -> dict[str, Any]: compiles score, counts, and categorized asset lists.
#
# Rules and edge cases:
# - Calculation weights:
#   * Critical findings: heavily weighted (e.g. 10.0 points each or 100% impact), covering Shor-vulnerable asymmetric crypto (RSA, ECC, Ed25519) and classically broken primitives (MD5, SHA-1, AES-ECB).
#   * Medium findings: moderately weighted (e.g. 3.0 points each or 30% impact), covering Grover-vulnerable symmetric ciphers with insufficient key length (AES-128).
#   * Safe findings: zero penalty weight (0.0 points), covering AES-256, SHA-384, SHA-512, and PQC-native algorithms.
# - If zero findings are present, overall score should cleanly reflect 0 (or safe baseline) rather than dividing by zero.
# - Findings with "unknown" risk should be tracked in a separate category and reported transparently.
#
# Scoring link:
# - Usability and demo (15%): Provides an executive-ready numeric score and clear risk breakdowns for live presentations.
# - Accuracy (40%): Applies rigorous, transparent mathematical weighting to avoid misrepresenting quantum posture.

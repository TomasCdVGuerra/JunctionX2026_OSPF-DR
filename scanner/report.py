"""Aggregate security metrics, posture evaluation, and reporting layer."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from scanner.models import QuantumRiskLevel

# Score calculation weights (0.0 to 1.0 exposure model)
CRITICAL_WEIGHT: float = 1.0
MEDIUM_WEIGHT: float = 0.3
SAFE_WEIGHT: float = 0.0
UNKNOWN_WEIGHT: float = 0.0

# Dashboard hygiene formula weights
HYGIENE_CRITICAL_WEIGHT: float = 100.0
HYGIENE_MEDIUM_WEIGHT: float = 30.0

# Canonical display risk ordering
RISK_TIERS: tuple[str, ...] = ("Critical", "Medium", "Safe", "Unknown")


def summarize_scan_coverage(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe input processing independently of finding risk/assessment coverage."""
    complete_statuses = {"With findings", "No detections"}
    total = len(outcomes)
    completed = sum(row.get("Status") in complete_statuses for row in outcomes)
    failed = sum(row.get("Status") == "Failed" for row in outcomes)
    skipped = sum(row.get("Status") == "Skipped" for row in outcomes)
    limited = sum(row.get("Status") in complete_statuses and row.get("Scanner") == "FALLBACK heuristic"
                  for row in outcomes)
    unrecorded = total - completed - failed - skipped
    status = "Unknown" if not total else "Partial" if failed or skipped or limited or unrecorded else "Complete"
    return {"status": status, "total_inputs": total, "completed_inputs": completed,
            "failed_inputs": failed, "skipped_inputs": skipped, "limited_inputs": limited,
            "unrecorded_inputs": unrecorded}


def _unwrap_enum(value: Any) -> Any:
    """Return raw string value if value is an Enum instance."""
    return getattr(value, "value", value)


def _json_safe(obj: Any) -> Any:
    """Recursively convert model, enum, and path objects into pure JSON primitives."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(item) for item in obj]
    return obj


def _extract_risk_tier(finding: Any, risk_field: str = "quantum_risk") -> str:
    """Extract and normalize risk tier string from finding model or dictionary."""
    raw_val: Any = None
    if risk_field != "quantum_risk":
        if isinstance(finding, dict):
            raw_val = finding.get(risk_field)
            present = risk_field in finding
        else:
            raw_val = getattr(finding, risk_field, None)
            present = hasattr(finding, risk_field)
        if present:
            norm = str(_unwrap_enum(raw_val)).strip().capitalize()
            return norm if norm in RISK_TIERS else "Unknown"
        # Legacy reports supplied only one risk field.
        return _extract_risk_tier(finding)
    if isinstance(finding, dict):
        raw_val = (
            finding.get("quantum_risk")
            or finding.get("risk_rating")
            or finding.get("risk")
        )
    else:
        raw_val = (
            getattr(finding, "quantum_risk", None)
            or getattr(finding, "risk_rating", None)
            or getattr(finding, "risk", None)
        )

    if raw_val is None:
        return "Unknown"

    norm = str(_unwrap_enum(raw_val)).strip().capitalize()
    if norm in RISK_TIERS:
        return norm
    return "Unknown"


def _serialize_finding(finding: Any) -> dict[str, Any]:
    """Serialize finding object to a JSON-safe dictionary preserving evidence."""
    if hasattr(finding, "to_dict") and callable(finding.to_dict):
        raw_dict = finding.to_dict()
    elif hasattr(finding, "model_dump") and callable(finding.model_dump):
        raw_dict = finding.model_dump(mode="json")
    elif isinstance(finding, dict):
        raw_dict = dict(finding)
    elif hasattr(finding, "__dict__"):
        raw_dict = {
            k: v for k, v in finding.__dict__.items() if not k.startswith("_")
        }
    else:
        raw_dict = {"finding": str(finding)}

    return _json_safe(raw_dict)


def risk_weight(risk: QuantumRiskLevel | str | None) -> float:
    """Return numeric exposure weight for a given risk level."""
    if risk is None:
        return UNKNOWN_WEIGHT
    tier = str(_unwrap_enum(risk)).strip().lower()
    if tier == "critical":
        return CRITICAL_WEIGHT
    if tier == "medium":
        return MEDIUM_WEIGHT
    if tier == "safe":
        return SAFE_WEIGHT
    return UNKNOWN_WEIGHT


def generate_summary_counts(
    findings: list[Any],
    risk_field: str = "quantum_risk",
) -> dict[str, int]:
    """Return count mapping partitioned by risk tier and total findings.

    Returns:
        Dictionary with keys 'Critical', 'Medium', 'Safe', 'Unknown', 'Total'.
    """
    counts: dict[str, int] = {
        "Critical": 0,
        "Medium": 0,
        "Safe": 0,
        "Unknown": 0,
        "Total": 0,
    }

    if not findings:
        return counts

    for finding in findings:
        tier = _extract_risk_tier(finding, risk_field)
        counts[tier] = counts.get(tier, 0) + 1
        counts["Total"] += 1

    return counts


def calculate_quantum_risk_score(
    findings: list[Any],
) -> float:
    """Calculate normalized Quantum Risk Score (0.0 to 100.0).

    This is an exposure score where higher values represent greater risk:
    - Scores only assessed quantum findings; classical risk is separate.
    - Unknown findings are excluded from the denominator and shown as coverage.
    - 0.0 with zero coverage does not imply safety.

    Returns:
        Normalized score rounded to two decimal places, or 0.0 for empty input.
    """
    if not findings:
        return 0.0

    counts = generate_summary_counts(findings)
    total = counts["Total"] - counts["Unknown"]
    if total == 0:
        return 0.0

    weighted_sum = (
        counts["Critical"] * CRITICAL_WEIGHT
        + counts["Medium"] * MEDIUM_WEIGHT
        + counts["Safe"] * SAFE_WEIGHT
        + counts["Unknown"] * UNKNOWN_WEIGHT
    )

    score = (weighted_sum / total) * 100.0
    return round(score, 2)


def calculate_hygiene_score(
    findings: list[Any],
) -> int:
    """Calculate overall Crypto Hygiene health score (0 to 100).

    Higher values represent healthier posture:
    - Measures classical assessment with a coverage penalty for unknown assets.
    - 100 means all inventoried assets are classically safe in assessed criteria.
    - 0 can mean critical findings or lack of verification; it is not proof of compromise.
    - Empty input returns 0 and posture NO_DATA.
    """
    if not findings:
        return 0

    counts = generate_summary_counts(findings, "classical_risk")
    total = counts["Total"]
    if total == 0:
        return 0

    penalty = (
        counts["Critical"] * HYGIENE_CRITICAL_WEIGHT
        + counts["Medium"] * HYGIENE_MEDIUM_WEIGHT
        + counts["Unknown"] * 100.0
    ) / total

    raw_score = 100.0 - penalty
    return max(0, int(raw_score))


def calculate_posture_status(
    findings: list[Any],
) -> str:
    """Determine deterministic machine-readable cryptographic posture status.

    Returns:
        - 'FAILING': At least one Critical finding detected (Shor-vulnerable or broken).
        - 'AT_RISK': No Critical findings, but quantum-vulnerable findings detected.
        - 'SECURE': Non-empty findings with zero Critical or quantum-vulnerable findings.
        - 'NO_DATA': Empty findings inventory.
        - 'INCOMPLETE': No known elevated risk but an assessment is unknown.
    """
    if not findings:
        return "NO_DATA"

    counts = generate_summary_counts(findings)
    classical_counts = generate_summary_counts(findings, "classical_risk")
    if counts["Total"] == 0:
        return "NO_DATA"

    if counts["Critical"] > 0 or classical_counts["Critical"] > 0:
        return "FAILING"

    # Check for Grover/quantum-vulnerable primitives (Medium tier or explicit flag)
    has_quantum_vulnerable = counts["Medium"] > 0 or classical_counts["Medium"] > 0
    if not has_quantum_vulnerable:
        for f in findings:
            if isinstance(f, dict):
                qv = f.get("quantum_vulnerable")
                if qv is True or str(qv).lower() == "true":
                    has_quantum_vulnerable = True
                    break
            else:
                qv = getattr(f, "quantum_vulnerable", None)
                if qv is True or str(qv).lower() == "true":
                    has_quantum_vulnerable = True
                    break

    if has_quantum_vulnerable:
        return "AT_RISK"

    if counts["Unknown"] > 0 or classical_counts["Unknown"] > 0:
        return "INCOMPLETE"

    return "SECURE"


def categorize_findings(
    findings: list[Any],
) -> dict[str, list[dict[str, Any]]]:
    """Group serialized findings into categorized lists by risk tier."""
    categories: dict[str, list[dict[str, Any]]] = {
        "critical": [],
        "medium": [],
        "safe": [],
        "unknown": [],
    }

    for finding in findings:
        tier = _extract_risk_tier(finding).lower()
        serialized = _serialize_finding(finding)
        if tier in categories:
            categories[tier].append(serialized)
        else:
            categories["unknown"].append(serialized)

    return categories


def group_by_source(
    findings: list[Any],
) -> dict[str, int]:
    """Group finding counts deterministically by source type."""
    groups: dict[str, int] = {}
    for finding in findings:
        st_val: Any = None
        if isinstance(finding, dict):
            st_val = finding.get("source_type")
        else:
            st_val = getattr(finding, "source_type", None)

        source_type = str(_unwrap_enum(st_val) or "unknown").strip()
        groups[source_type] = groups.get(source_type, 0) + 1

    return dict(sorted(groups.items()))


def group_by_algorithm(
    findings: list[Any],
) -> dict[str, int]:
    """Group finding counts deterministically by canonical algorithm name."""
    groups: dict[str, int] = {}
    for finding in findings:
        algo_val: Any = None
        if isinstance(finding, dict):
            algo_val = (
                finding.get("algorithm_name")
                or finding.get("canonical_algorithm")
                or finding.get("algorithm")
            )
        else:
            algo_val = (
                getattr(finding, "algorithm_name", None)
                or getattr(finding, "canonical_algorithm", None)
                or getattr(finding, "algorithm", None)
            )

        algo_name = str(_unwrap_enum(algo_val) or "unknown").strip()
        groups[algo_name] = groups.get(algo_name, 0) + 1

    # Deterministic sort: frequency descending, then algorithm name ascending
    return dict(sorted(groups.items(), key=lambda kv: (-kv[1], kv[0])))


def build_report_summary(
    findings: list[Any],
) -> dict[str, Any]:
    """Compile comprehensive JSON-serializable report summary dictionary.

    Returns:
        Structured dictionary matching report schema with serialized findings.
    """
    counts = generate_summary_counts(findings)
    categorized = categorize_findings(findings)
    risk_score = calculate_quantum_risk_score(findings)
    hygiene_score = calculate_hygiene_score(findings)
    posture_status = calculate_posture_status(findings)
    classical_counts = generate_summary_counts(findings, "classical_risk")

    return {
        "risk_score": risk_score,
        "hygiene_score": hygiene_score,
        "posture_status": posture_status,
        "counts": counts,
        "classical_counts": classical_counts,
        "classical_coverage_percent": round(
            100 * (counts["Total"] - classical_counts["Unknown"]) / counts["Total"], 2
        ) if counts["Total"] else 0.0,
        "quantum_coverage_percent": round(
            100 * (counts["Total"] - counts["Unknown"]) / counts["Total"], 2
        ) if counts["Total"] else 0.0,
        "total_findings": counts["Total"],
        "critical_findings": categorized["critical"],
        "medium_findings": categorized["medium"],
        "safe_findings": categorized["safe"],
        "unknown_findings": categorized["unknown"],
        "by_source_type": group_by_source(findings),
        "by_algorithm": group_by_algorithm(findings),
    }

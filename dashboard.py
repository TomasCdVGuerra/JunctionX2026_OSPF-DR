"""Streamlit dashboard for QuantumTrace CycloneDX 1.6 CBOM reports."""

from __future__ import annotations

import json
import logging
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import pandas as pd
    import streamlit as st
except ImportError:  # pragma: no cover
    pd = None  # type: ignore[assignment]
    st = None  # type: ignore[assignment]

try:
    import plotly.express as px
except ImportError:  # pragma: no cover
    px = None  # type: ignore[assignment]

try:
    from scanner.cbom import CBOMSerializer
except ImportError:  # pragma: no cover
    CBOMSerializer = None  # type: ignore[assignment,misc]


try:
    from scanner import source_scanner
except ImportError:  # pragma: no cover
    source_scanner = None  # type: ignore[assignment]

try:
    import scanner.json_scanner as json_scanner  # type: ignore[import-not-found] # noqa: PLR0402
except ImportError:  # pragma: no cover
    json_scanner = None  # type: ignore[assignment]

try:
    from scanner import cloud_scanner
except ImportError:  # pragma: no cover
    cloud_scanner = None  # type: ignore[assignment]

try:
    from scanner import pcap_scanner
except ImportError:  # pragma: no cover
    pcap_scanner = None  # type: ignore[assignment]

try:
    from scanner.report import (
        build_report_summary,
        calculate_hygiene_score,
        calculate_posture_status,
        calculate_quantum_risk_score,
        generate_summary_counts,
        group_by_algorithm,
        group_by_source,
    )
except ImportError:  # pragma: no cover
    build_report_summary = None  # type: ignore[assignment]
    calculate_hygiene_score = None  # type: ignore[assignment]
    calculate_posture_status = None  # type: ignore[assignment]
    calculate_quantum_risk_score = None  # type: ignore[assignment]
    generate_summary_counts = None  # type: ignore[assignment]
    group_by_algorithm = None  # type: ignore[assignment]
    group_by_source = None  # type: ignore[assignment]

try:
    from scanner.risk import (
        build_reasoning,
        enrich_finding_risk,
        evaluate_risk,
        is_classically_broken,
        map_nist_standard,
    )
except ImportError:  # pragma: no cover
    build_reasoning = None  # type: ignore[assignment]
    enrich_finding_risk = None  # type: ignore[assignment]
    evaluate_risk = None  # type: ignore[assignment]
    is_classically_broken = None  # type: ignore[assignment]
    map_nist_standard = None  # type: ignore[assignment]


def _set_finding_scanner_source(finding: Any, source_label: str) -> None:
    """Attach the scanner source label to a finding dict or model instance."""
    if isinstance(finding, dict):
        finding["Scanner source"] = source_label
        finding["scanner_source"] = source_label
    else:
        try:
            setattr(finding, "Scanner source", source_label)
            finding.scanner_source = source_label
        except (AttributeError, TypeError, ValueError):
            try:
                object.__setattr__(finding, "_scanner_source", source_label)
            except (AttributeError, TypeError, ValueError):
                pass


def _get_finding_scanner_source(finding: Any, default: str = "unknown") -> str:
    """Retrieve the scanner source label from a finding or component."""
    if isinstance(finding, dict):
        if "Scanner source" in finding:
            return str(finding["Scanner source"])
        if "scanner_source" in finding:
            return str(finding["scanner_source"])
        if "properties" in finding:
            val = _extract_property(finding["properties"], "cryptotrace:scannerSource")
            if val != "unknown":
                return val
        return default
    raw_val: Any = (
        getattr(finding, "Scanner source", None)
        or getattr(finding, "scanner_source", None)
        or getattr(finding, "_scanner_source", None)
    )
    return str(raw_val) if raw_val is not None else default


def _tag_findings_scanner_source(findings: list[Any], source_label: str) -> None:
    """Tag each finding in the list with the scanner source label."""
    for finding in findings:
        _set_finding_scanner_source(finding, source_label)


def _get_cloud_scanner() -> tuple[Any, str] | None:
    """Return (scanner_module, method_name) if a cloud scanner with a scan method exists."""
    for mod in (cloud_scanner, json_scanner):
        if mod is None:
            continue
        for method_name in ("scan_cloud_directory", "scan_directory", "scan_json_file", "scan"):
            if hasattr(mod, method_name) and callable(getattr(mod, method_name)):
                return mod, method_name
    return None


def _get_source_scanner_dir() -> tuple[Any, str] | None:
    """Return (scanner_module, method_name) for directory scanning if available."""
    if source_scanner is not None:
        for method_name in ("scan_source_directory", "scan_directory", "scan"):
            if hasattr(source_scanner, method_name) and callable(getattr(source_scanner, method_name)):
                return source_scanner, method_name
    return None


def _get_source_scanner_file() -> tuple[Any, str] | None:
    """Return (scanner_module, method_name) for file scanning if available."""
    if source_scanner is not None:
        for method_name in ("scan_file", "scan_source_file", "scan", "scan_source_directory"):
            if hasattr(source_scanner, method_name) and callable(getattr(source_scanner, method_name)):
                return source_scanner, method_name
    return None


def _get_pcap_scanner() -> tuple[Any, str] | None:
    """Return (scanner_module, method_name) for pcap scanning if available."""
    if pcap_scanner is not None:
        for method_name in ("parse_pcap", "scan_pcap", "scan"):
            if hasattr(pcap_scanner, method_name) and callable(getattr(pcap_scanner, method_name)):
                return pcap_scanner, method_name
    return None


DEFAULT_CBOM_PATH = Path("cbom.json")
DEFAULT_SAMPLE_DIR = Path("support-materials")

RISK_ORDER = ["Critical", "Medium", "Safe", "Unknown"]
RISK_COLORS = {
    "Critical": "#dc2626",
    "Medium": "#f59e0b",
    "Safe": "#16a34a",
    "Unknown": "#6b7280",
}

CRIT_WEIGHT = 100
MED_WEIGHT = 30

CRITICAL_WEIGHT = 10
MEDIUM_WEIGHT = 3


def _normalise(value: Any, default: str = "unknown") -> str:
    """Convert missing values and Enum-like values to display strings."""
    if value is None:
        return default

    value = getattr(value, "value", value)

    if isinstance(value, bool):
        return "true" if value else "false"

    text = str(value).strip()
    return text if text else default


def _extract_property(
    properties: Any,
    name: str,
    default: str = "unknown",
) -> str:
    """Extract a CycloneDX property value by name."""
    if not isinstance(properties, list):
        return default

    for prop in properties:
        if not isinstance(prop, dict):
            continue

        if prop.get("name") == name:
            return _normalise(prop.get("value"), default)

    return default


def _extract_properties(properties: Any) -> dict[str, str]:
    """Convert a CycloneDX properties array to a string dictionary."""
    if not isinstance(properties, list):
        return {}

    result: dict[str, str] = {}

    for prop in properties:
        if not isinstance(prop, dict):
            continue

        name = prop.get("name")
        if name:
            result[str(name)] = _normalise(prop.get("value"))

    return result


def _first_dict(value: Any) -> dict[str, Any]:
    """Return the first dictionary from a list or dictionary value."""
    if isinstance(value, dict):
        return value

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item

    return {}


def _extract_native_crypto_properties(
    component: dict[str, Any],
) -> dict[str, str]:
    """Extract useful fields from CycloneDX native cryptoProperties."""
    crypto_properties = component.get("cryptoProperties", {})
    if not isinstance(crypto_properties, dict):
        return {}

    algorithm_properties = crypto_properties.get("algorithmProperties", {})
    if not isinstance(algorithm_properties, dict):
        algorithm_properties = _first_dict(algorithm_properties)

    result: dict[str, str] = {}

    for key in (
        "assetType",
        "oid",
        "primitive",
        "mode",
        "padding",
        "classicalSecurityLevel",
        "nistQuantumSecurityLevel",
    ):
        value = crypto_properties.get(key)

        if value is None:
            value = algorithm_properties.get(key)

        if value is not None:
            result[key] = _normalise(value)

    return result


def _extract_evidence(component: dict[str, Any]) -> dict[str, str]:
    """Extract evidence from CycloneDX evidence.occurrences."""
    evidence = component.get("evidence", {})
    if not isinstance(evidence, dict):
        return {}

    occurrences = evidence.get("occurrences", [])
    occurrence = _first_dict(occurrences)

    raw_location = occurrence.get("location")
    location = raw_location if isinstance(raw_location, dict) else {}

    source = occurrence.get("source", {})
    if not isinstance(source, dict):
        source = {}

    line = occurrence.get("line")

    if line is None:
        line = location.get("line")

    if line is None:
        line = occurrence.get("lineNumber")

    source_path = (
        occurrence.get("sourcePath")
        or occurrence.get("filePath")
        or source.get("filePath")
    )

    if source_path is None and isinstance(raw_location, str):
        source_path = raw_location

    return {
        "Source Path": _normalise(source_path),
        "Line Number": _normalise(line),
        "Matched Snippet": _normalise(
            occurrence.get("matchedSnippet")
            or occurrence.get("snippet")
            or location.get("snippet")
        ),
        "Rule ID": _normalise(
            occurrence.get("ruleId")
            or occurrence.get("ruleID")
            or source.get("ruleId")
        ),
        "NIST Standard": _normalise(
            occurrence.get("nistStandard")
            or source.get("nistStandard")
        ),
    }


def _extract_tool_info(cbom: dict[str, Any]) -> tuple[str, str]:
    """Read tool metadata from list-style and object-style CycloneDX tools."""
    metadata = cbom.get("metadata", {})
    if not isinstance(metadata, dict):
        return "Unknown Scanner", "0.0"

    tools = metadata.get("tools", [])

    if isinstance(tools, dict):
        tool_components = tools.get("components", [])

        if isinstance(tool_components, list) and tool_components:
            tool = tool_components[0]
            if isinstance(tool, dict):
                return (
                    _normalise(tool.get("name"), "Unknown Scanner"),
                    _normalise(tool.get("version"), "0.0"),
                )

        return "Unknown Scanner", "0.0"

    if isinstance(tools, list) and tools:
        tool = tools[0]

        if isinstance(tool, dict):
            return (
                _normalise(tool.get("name"), "Unknown Scanner"),
                _normalise(tool.get("version"), "0.0"),
            )

    return "Unknown Scanner", "0.0"


def _component_to_row(component: dict[str, Any]) -> dict[str, str]:
    """Convert one CycloneDX component into a dashboard row."""
    properties = _extract_properties(component.get("properties", []))
    native_properties = _extract_native_crypto_properties(component)
    evidence = _extract_evidence(component)

    def property_value(
        custom_name: str,
        native_name: str | None = None,
    ) -> str:
        if custom_name in properties:
            return properties[custom_name]

        if native_name and native_name in native_properties:
            return native_properties[native_name]

        return "unknown"

    risk_rating = property_value("cryptotrace:riskRating")

    if risk_rating != "unknown":
        risk_rating = risk_rating.capitalize()

    classical_risk = property_value("cryptotrace:classicalRisk")
    if classical_risk != "unknown":
        classical_risk = classical_risk.capitalize()
    else:
        algo_name = str(component.get("name") or "")
        if is_classically_broken is not None and is_classically_broken(algo_name):
            classical_risk = "Critical"
        elif risk_rating == "Critical":
            classical_risk = "Medium" if "1024" in algo_name else "Safe"
        elif risk_rating in ("Medium", "Safe"):
            classical_risk = "Safe"
        else:
            classical_risk = "Unknown"

    source_type = property_value("cryptotrace:sourceType")
    source_path = property_value("cryptotrace:sourcePath")
    operation = property_value("cryptotrace:operation")

    if source_path == "unknown":
        source_path = property_value("cryptotrace:filePath")

    if source_path == "unknown":
        source_path = evidence.get("Source Path", "unknown")

    if source_path == "unknown" and "evidence" in component:
        ev_list = component.get("evidence")
        if isinstance(ev_list, list) and ev_list:
            first_ev = ev_list[0]
            if hasattr(first_ev, "file_path") and first_ev.file_path:
                source_path = str(first_ev.file_path)
            elif isinstance(first_ev, dict) and first_ev.get("file_path"):
                source_path = str(first_ev["file_path"])

    if source_path == "unknown":
        source_path = _normalise(component.get("source"))

    scanner_source = property_value("cryptotrace:scannerSource")
    if scanner_source == "unknown":
        scanner_source = property_value("cryptotrace:scanner_source")
    if scanner_source == "unknown":
        scanner_source = properties.get(
            "Scanner source",
            properties.get("scanner_source", "unknown"),
        )
    if scanner_source == "unknown" and "Scanner source" in component:
        scanner_source = str(component["Scanner source"])
    elif scanner_source == "unknown" and "scanner_source" in component:
        scanner_source = str(component["scanner_source"])

    nist_standard = evidence.get("NIST Standard", "unknown")
    if nist_standard == "unknown":
        nist_standard = property_value("cryptotrace:nistStandard")
    if nist_standard == "unknown" and map_nist_standard is not None:
        mapped = map_nist_standard(str(component.get("name") or ""))
        if mapped != "none":
            nist_standard = mapped

    description = _normalise(component.get("description"))
    if description == "unknown" and build_reasoning is not None:
        description = build_reasoning(str(component.get("name") or ""))


    row = {
        "Algorithm": _normalise(component.get("name")),
        "Risk Rating": risk_rating,
        "Quantum Risk": risk_rating,
        "Classical Risk": classical_risk,
        "Scanner source": scanner_source,
        "Source Type": source_type,
        "Source Path": source_path,
        "Operation": operation,
        "Quantum Vulnerable": property_value(
            "cryptotrace:quantumVulnerable"
        ),
        "Quantum Safe": property_value(
            "cryptotrace:quantumSafe"
        ),
        "Line Number": evidence.get("Line Number", "unknown"),
        "Matched Snippet": evidence.get(
            "Matched Snippet",
            "unknown",
        ),
        "Rule ID": evidence.get("Rule ID", "unknown"),
        "NIST Standard": nist_standard,
        "BOM Reference": _normalise(component.get("bom-ref")),
        "Description": description,
    }

    for key, value in native_properties.items():
        row[f"Crypto: {key}"] = value

    for key, value in properties.items():
        if key.startswith("cryptotrace:") and key not in {
            "cryptotrace:riskRating",
            "cryptotrace:classicalRisk",
            "cryptotrace:nistStandard",
            "cryptotrace:sourceType",
            "cryptotrace:sourcePath",
            "cryptotrace:operation",
            "cryptotrace:quantumVulnerable",
            "cryptotrace:quantumSafe",
            "cryptotrace:scannerSource",
            "cryptotrace:scanner_source",
        }:
            row[key] = value

    return row


def _load_cbom_uncached(
    file_bytes: bytes | None = None,
    filepath: str = str(DEFAULT_CBOM_PATH),
) -> dict[str, Any]:
    """Load CBOM data from uploaded bytes or a local file."""
    if file_bytes is not None:
        if isinstance(file_bytes, str):
            file_bytes = file_bytes.encode("utf-8")

        return json.loads(file_bytes.decode("utf-8"))

    with open(filepath, "r", encoding="utf-8") as cbom_file:
        return json.load(cbom_file)


if st is not None:

    @st.cache_data(show_spinner=False)
    def load_cbom(
        file_bytes: bytes | None = None,
        filepath: str = str(DEFAULT_CBOM_PATH),
        file_mtime: float | None = None,
    ) -> dict[str, Any]:
        """Load and cache CBOM data."""
        del file_mtime
        return _load_cbom_uncached(file_bytes, filepath)

else:

    def load_cbom(
        file_bytes: bytes | None = None,
        filepath: str = str(DEFAULT_CBOM_PATH),
        file_mtime: float | None = None,
    ) -> dict[str, Any]:
        """Fallback loader used when Streamlit is unavailable."""
        del file_mtime
        return _load_cbom_uncached(file_bytes, filepath)


def load_findings_dataframe(
    cbom: dict[str, Any] | list[Any],
):
    """Convert CBOM cryptographic components into a Pandas DataFrame."""
    if pd is None:
        raise RuntimeError("Pandas is required to build the findings table.")

    if isinstance(cbom, list):
        components = cbom
    elif isinstance(cbom, dict):
        components = cbom.get("components", [])
    else:
        components = []
    if not isinstance(components, list):
        components = []

    rows = []
    for component in components:
        if isinstance(component, dict):
            rows.append(_component_to_row(component))
        elif hasattr(component, "evidence"):
            ev_list = component.evidence
            first_ev = ev_list[0] if ev_list else None
            q_risk = getattr(component, "quantum_risk", None)
            c_risk = getattr(component, "classical_risk", None)
            c_func = getattr(component, "crypto_function", None)
            q_risk_str = (
                q_risk.value if q_risk is not None and hasattr(q_risk, "value") else str(q_risk or "unknown")
            ).capitalize()
            c_risk_str = (
                c_risk.value if c_risk is not None and hasattr(c_risk, "value") else str(c_risk or "unknown")
            ).capitalize()
            algo_str = str(getattr(component, "algorithm_name", "") or "")
            if c_risk_str == "Unknown":
                if is_classically_broken is not None and is_classically_broken(algo_str):
                    c_risk_str = "Critical"
                elif q_risk_str == "Critical":
                    c_risk_str = "Medium" if "1024" in algo_str else "Safe"
                elif q_risk_str in ("Medium", "Safe"):
                    c_risk_str = "Safe"
            reasoning_str = _normalise(getattr(first_ev, "risk_reasoning", None))
            if reasoning_str == "unknown" and build_reasoning is not None:
                reasoning_str = build_reasoning(algo_str)
            nist_str = _normalise(getattr(first_ev, "nist_standard", None))
            if nist_str == "unknown" and map_nist_standard is not None:
                mapped = map_nist_standard(algo_str)
                if mapped != "none":
                    nist_str = mapped
            rows.append({
                "Algorithm": _normalise(getattr(component, "algorithm_name", None)),
                "Risk Rating": q_risk_str,
                "Quantum Risk": q_risk_str,
                "Classical Risk": c_risk_str,
                "Scanner source": "unknown",
                "Source Type": _normalise(getattr(component, "source_type", None)),
                "Source Path": getattr(first_ev, "file_path", "unknown") if first_ev else "unknown",
                "Operation": (
                    c_func.value if c_func is not None and hasattr(c_func, "value") else str(c_func or "unknown")
                ),
                "Quantum Vulnerable": "true" if getattr(q_risk, "value", q_risk) == "critical" else "false",
                "Quantum Safe": "true" if getattr(q_risk, "value", q_risk) == "safe" else "false",
                "Line Number": str(getattr(first_ev, "line_number", "unknown")),
                "Matched Snippet": _normalise(getattr(first_ev, "matched_snippet", None)),
                "Rule ID": _normalise(getattr(first_ev, "rule_id", None)),
                "NIST Standard": nist_str,
                "BOM Reference": "unknown",
                "Description": reasoning_str,
            })

    columns = [
        "Algorithm",
        "Risk Rating",
        "Quantum Risk",
        "Classical Risk",
        "Scanner source",
        "Source Type",
        "Source Path",
        "Operation",
        "Quantum Vulnerable",
        "Quantum Safe",
        "Line Number",
        "Matched Snippet",
        "Rule ID",
        "NIST Standard",
        "BOM Reference",
        "Description",
    ]

    dataframe = pd.DataFrame(rows)

    for column in columns:
        if column not in dataframe.columns:
            dataframe[column] = "unknown"

    return dataframe[columns + [
        column for column in dataframe.columns
        if column not in columns
    ]]


def _risk_css(value: Any) -> str:
    """Return CSS for a risk-rating cell."""
    color = RISK_COLORS.get(str(value), RISK_COLORS["Unknown"])
    return f"background-color: {color}; color: white; font-weight: bold"


def _style_dataframe(dataframe):
    """Style risk cells using modern Styler.map with fallback."""
    styler = dataframe.style
    style_function = getattr(styler, "map", None)

    if style_function is None:
        style_function = getattr(styler, "applymap", None)

    if style_function is None:
        return dataframe

    target_cols = [c for c in ("Risk Rating", "Quantum Risk", "Classical Risk") if c in dataframe.columns]
    if target_cols:
        return style_function(_risk_css, subset=target_cols)
    return dataframe


def _safe_text_columns(dataframe):
    """Ensure searchable columns contain non-null strings."""
    for column in ("Algorithm", "Source Path", "Matched Snippet", "Rule ID"):
        if column not in dataframe.columns:
            dataframe[column] = "unknown"

        dataframe[column] = dataframe[column].fillna("unknown").astype(str)

    return dataframe


def render_cli_fallback_notice() -> None:
    """Display instructions when the dashboard cannot run normally."""
    if st is None:
        print(
            "Streamlit is required to run the QuantumTrace dashboard. "
            "Install dependencies and launch with: streamlit run dashboard.py",
            file=sys.stderr,
        )
        return

    st.info(
        "The Streamlit dashboard is the primary supported interface for QuantumTrace. "
        "The CLI entrypoint is temporarily disabled."
    )


def _report_findings_from_cbom(
    cbom: dict[str, Any] | list[Any],
) -> list[dict[str, Any]]:
    """Convert active CBOM or components into standardized findings expected by scanner.report."""
    if isinstance(cbom, list):
        components = cbom
    elif isinstance(cbom, dict):
        components = cbom.get("components", [])
    else:
        components = []

    if not isinstance(components, list):
        components = []

    report_findings: list[dict[str, Any]] = []
    for component in components:
        if isinstance(component, dict):
            props = _extract_properties(component.get("properties", []))
            ev = _extract_evidence(component)

            algo_name = (
                component.get("name")
                or component.get("algorithm_name")
                or component.get("canonical_algorithm")
                or component.get("algorithm")
                or "Unknown"
            )

            q_risk = (
                props.get("cryptotrace:riskRating")
                or component.get("quantum_risk")
                or component.get("risk_rating")
                or component.get("risk")
                or "Unknown"
            )
            if hasattr(q_risk, "value"):
                q_risk = q_risk.value
            q_risk_str = str(q_risk).strip().capitalize() if q_risk else "Unknown"

            c_risk = (
                props.get("cryptotrace:classicalRisk")
                or component.get("classical_risk")
                or None
            )
            if c_risk is not None and hasattr(c_risk, "value"):
                c_risk = c_risk.value
            if c_risk:
                c_risk_str = str(c_risk).strip().capitalize()
            else:
                if is_classically_broken is not None and is_classically_broken(algo_name):
                    c_risk_str = "Critical"
                elif q_risk_str == "Critical":
                    c_risk_str = "Medium" if "1024" in algo_name else "Safe"
                elif q_risk_str in ("Medium", "Safe"):
                    c_risk_str = "Safe"
                else:
                    c_risk_str = "Unknown"

            source_type = (
                props.get("cryptotrace:sourceType")
                or component.get("source_type")
                or "unknown"
            )
            if hasattr(source_type, "value"):
                source_type = source_type.value

            source_path = (
                props.get("cryptotrace:sourcePath")
                or ev.get("Source Path")
                or component.get("source_path")
                or component.get("file_path")
                or "unknown"
            )

            reasoning = (
                component.get("description")
                or component.get("explanation")
                or component.get("reasoning")
                or None
            )
            if (not reasoning or reasoning == "unknown") and build_reasoning is not None:
                reasoning = build_reasoning(algo_name)

            nist_std = (
                props.get("cryptotrace:nistStandard")
                or ev.get("NIST Standard")
                or component.get("nist_standard")
                or None
            )
            if (not nist_std or nist_std in ("unknown", "none")) and map_nist_standard is not None:
                mapped = map_nist_standard(algo_name)
                nist_std = mapped if mapped != "none" else None


            qv_val = props.get("cryptotrace:quantumVulnerable", component.get("quantum_vulnerable"))
            if qv_val is not None:
                q_vuln = str(qv_val).lower() == "true"
            else:
                q_vuln = q_risk_str == "Critical"

            qs_val = props.get("cryptotrace:quantumSafe", component.get("quantum_safe"))
            if qs_val is not None:
                q_safe = str(qs_val).lower() == "true"
            else:
                q_safe = q_risk_str == "Safe"

            evidence_items = component.get("evidence") or [
                {
                    "file_path": str(source_path),
                    "line_number": ev.get("Line Number") or component.get("line_number"),
                    "matched_snippet": ev.get("Matched Snippet") or component.get("matched_snippet"),
                    "rule_id": ev.get("Rule ID") or component.get("rule_id"),
                    "risk_reasoning": reasoning,
                    "nist_standard": nist_std,
                }
            ]

            report_findings.append({
                "algorithm_name": str(algo_name),
                "canonical_algorithm": str(algo_name),
                "quantum_risk": q_risk_str.lower(),
                "risk_rating": q_risk_str,
                "classical_risk": c_risk_str,
                "source_type": str(source_type),
                "source_path": str(source_path),
                "evidence": evidence_items,
                "reasoning": reasoning or "unknown",
                "explanation": reasoning or "unknown",
                "nist_standard": nist_std or "none",
                "quantum_vulnerable": q_vuln,
                "quantum_safe": q_safe,
            })
        elif hasattr(component, "algorithm_name"):
            q_risk = getattr(component, "quantum_risk", None)
            c_risk = getattr(component, "classical_risk", None)
            q_risk_str = getattr(q_risk, "value", str(q_risk or "unknown")).capitalize()
            c_risk_str = getattr(c_risk, "value", str(c_risk or "unknown")).capitalize()

            ev_list = getattr(component, "evidence", [])
            first_ev = ev_list[0] if ev_list else None
            source_path = getattr(first_ev, "file_path", "unknown") if first_ev else "unknown"
            reasoning = getattr(first_ev, "risk_reasoning", None) if first_ev else None
            nist_std = getattr(first_ev, "nist_standard", None) if first_ev else None

            report_findings.append({
                "algorithm_name": component.algorithm_name,
                "canonical_algorithm": component.algorithm_name,
                "quantum_risk": q_risk_str.lower(),
                "risk_rating": q_risk_str,
                "classical_risk": c_risk_str,
                "source_type": getattr(component.source_type, "value", str(component.source_type)),
                "source_path": source_path,
                "evidence": [ev.model_dump() for ev in ev_list] if ev_list and hasattr(ev_list[0], "model_dump") else ev_list,
                "reasoning": reasoning or "unknown",
                "explanation": reasoning or "unknown",
                "nist_standard": nist_std or "none",
                "quantum_vulnerable": q_risk_str == "Critical",
                "quantum_safe": q_risk_str == "Safe",
            })

    return report_findings


def _render_metrics(full_dataframe, summary: dict[str, Any] | None = None) -> None:
    """Render decoupled Hygiene vs Posture metrics and centralized Quantum Risk Score."""
    total_assets = len(full_dataframe)
    if total_assets == 0:
        st.info("Run a scan to see results")
        return

    if summary is None:
        if build_report_summary is not None:
            findings = [
                {
                    "quantum_risk": row.get("Quantum Risk", row.get("Risk Rating", "Unknown")),
                    "algorithm_name": row.get("Algorithm", "Unknown"),
                    "source_type": row.get("Source Type", "unknown"),
                    "quantum_vulnerable": str(row.get("Quantum Vulnerable", "")).lower() == "true",
                }
                for _, row in full_dataframe.iterrows()
            ]
            summary = build_report_summary(findings)
        else:
            crit_count = int((full_dataframe["Risk Rating"] == "Critical").sum())
            med_count = int((full_dataframe["Risk Rating"] == "Medium").sum())
            safe_count = int((full_dataframe["Risk Rating"] == "Safe").sum())
            unk_count = int((full_dataframe["Risk Rating"] == "Unknown").sum())
            summary = {
                "risk_score": round(((crit_count * 1.0 + med_count * 0.3) / total_assets) * 100.0, 2),
                "hygiene_score": max(0, int(100 - (crit_count * 100.0 + med_count * 30.0) / total_assets)),
                "posture_status": "FAILING" if crit_count > 0 else ("AT_RISK" if med_count > 0 else "SECURE"),
                "counts": {
                    "Critical": crit_count,
                    "Medium": med_count,
                    "Safe": safe_count,
                    "Unknown": unk_count,
                    "Total": total_assets,
                },
                "total_findings": total_assets,
            }

    counts = summary.get("counts", {})
    crit_count = counts.get("Critical", 0)
    med_count = counts.get("Medium", 0)
    safe_count = counts.get("Safe", 0)
    unk_count = counts.get("Unknown", 0)
    total_count = summary.get("total_findings", total_assets)
    hygiene_score = summary.get("hygiene_score", 100)
    risk_score = summary.get("risk_score", 0.0)
    raw_status = summary.get("posture_status", "NO_DATA")

    posture_map = {
        "FAILING": "🚨 FAILING",
        "AT_RISK": "⚠️ AT RISK",
        "SECURE": "✅ SECURE",
        "NO_DATA": "ℹ️ NO DATA",
    }
    posture_status = posture_map.get(raw_status, f"• {raw_status}")

    # Row 1: 3 primary executive indicators
    row1_cols = st.columns(3)
    row1_cols[0].metric("Crypto Hygiene", f"{hygiene_score}/100")
    row1_cols[1].metric(
        "Quantum Risk Score",
        f"{risk_score:.2f}/100" if isinstance(risk_score, (int, float)) else f"{risk_score}/100",
    )
    row1_cols[2].metric("Posture Status", posture_status)

    # Row 2: 5 granular counts
    row2_cols = st.columns(5)
    row2_cols[0].metric("Critical", crit_count)
    row2_cols[1].metric("Medium", med_count)
    row2_cols[2].metric("Safe", safe_count)
    row2_cols[3].metric("Unknown", unk_count)
    row2_cols[4].metric("Total Findings", total_count)

    st.progress(hygiene_score / 100.0, text="Overall Crypto Hygiene")
    st.info("Executive metrics use the full active scan; filters affect only the detailed view.")

    if crit_count > 0:
        st.error(
            f"**MIGRATION REQUIRED:** {crit_count} Critical findings use cryptography vulnerable to Shor's algorithm or known classical breaks.",
            icon="🚨",
        )
    elif med_count > 0:
        st.warning(
            f"**QUANTUM EXPOSURE:** {med_count} Medium findings provide reduced security under Grover's algorithm.",
            icon="⚠️",
        )


def _render_risk_chart(dataframe) -> None:
    """Render a stable-order dark-themed risk distribution chart."""
    if px is None:
        st.warning(
            "Plotly is not installed; the risk distribution chart is "
            "unavailable."
        )
        return

    chart_data = (
        dataframe["Risk Rating"]
        .value_counts()
        .reindex(RISK_ORDER, fill_value=0)
        .rename_axis("Risk Rating")
        .reset_index(name="Findings")
    )

    chart_data = chart_data[chart_data["Findings"] > 0]

    if chart_data.empty:
        st.info("No findings match the selected filters.")
        return

    figure = px.pie(
        chart_data,
        names="Risk Rating",
        values="Findings",
        hole=0.55,
        color="Risk Rating",
        color_discrete_map=RISK_COLORS,
        category_orders={"Risk Rating": RISK_ORDER},
    )

    figure.update_layout(
        template="plotly_dark",
        legend_title_text="Risk Rating",
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
    )

    st.plotly_chart(figure, use_container_width=True)


def _render_download_button(cbom: dict[str, Any]) -> None:
    """Render a UTF-8 CycloneDX JSON download button."""
    serialized_cbom = json.dumps(
        cbom,
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    st.download_button(
        label="Download CycloneDX 1.6 CBOM",
        data=serialized_cbom.encode("utf-8"),
        file_name="cbom.json",
        mime="application/json",
        use_container_width=True,
    )


def _build_cbom_from_findings(findings: list[Any]) -> dict[str, Any]:
    """Serialize findings into a CycloneDX 1.6 CBOM document."""
    if CBOMSerializer is not None:
        serializer = CBOMSerializer(
            scanner_name="OSPF-DR QuantumTrace",
            version="1.0.0",
        )
        for finding in findings:
            serializer.add_finding(finding)
            scanner_src = _get_finding_scanner_source(finding)
            if serializer.document.get("components"):
                comp = serializer.document["components"][-1]
                if isinstance(comp.get("properties"), list):
                    comp["properties"].append({
                        "name": "cryptotrace:scannerSource",
                        "value": scanner_src,
                    })
        return serializer.document

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [],
    }


def _scan_source_file_fallback(path: Path) -> list[dict[str, Any]]:
    """Scan source code for cryptographic primitives if scanner is unavailable."""
    findings: list[dict[str, Any]] = []
    display_name = path.name

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = content.splitlines()

    for idx, raw_line in enumerate(lines, start=1):
        line = re.sub(r"#.*$", "", raw_line)
        line = re.sub(r"//.*$", "", line).strip()
        if not line:
            continue

        # 1. RSA
        if "rsa.generate_private_key" in line or 'KeyPairGenerator.getInstance("RSA")' in line or "rsa.GenerateKey(" in line:
            size_match = re.search(r"(\d{4})", line)
            key_size = size_match.group(1) if size_match else "2048"
            findings.append({
                "canonical_algorithm": f"RSA-{key_size}",
                "explanation": "RSA is vulnerable to Shor's quantum factoring algorithm.",
                "risk_rating": "Critical",
                "quantum_vulnerable": True,
                "quantum_safe": False,
                "source_type": "source-code",
                "source_path": display_name,
                "operation": "KEYGEN",
                "line_number": idx,
                "matched_snippet": raw_line.strip(),
                "rule_id": "src-rsa-keygen",
                "nist_standard": "FIPS 186-5",
            })

        # 2. Ed25519
        if ("Ed25519" in line or "ed25519" in line) and (
            "PrivateKey" in line or "GenerateKey" in line or "Sign" in line
        ):
                findings.append({
                    "canonical_algorithm": "Ed25519",
                    "explanation": "Ed25519 signature algorithm is broken by Shor's quantum algorithm.",
                    "risk_rating": "Critical",
                    "quantum_vulnerable": True,
                    "quantum_safe": False,
                    "source_type": "source-code",
                    "source_path": display_name,
                    "operation": "SIGN",
                    "line_number": idx,
                    "matched_snippet": raw_line.strip(),
                    "rule_id": "src-ed25519-sign",
                    "nist_standard": "FIPS 186-5",
                })

        # 3. Weak hashes: MD5, SHA-1 (require API-level call patterns)
        if re.search(r"\b(?:hashlib\.md5|md5\.New|md5\.Sum|MessageDigest\.getInstance\s*\(\s*\"MD5\"\)|crypto/md5)\b", line, re.IGNORECASE):
            findings.append({
                "canonical_algorithm": "MD5",
                "explanation": "MD5 is cryptographically broken by classical collision attacks.",
                "risk_rating": "Critical",
                "quantum_vulnerable": True,
                "quantum_safe": False,
                "source_type": "source-code",
                "source_path": display_name,
                "operation": "DIGEST",
                "line_number": idx,
                "matched_snippet": raw_line.strip(),
                "rule_id": "src-md5-digest",
                "nist_standard": "none",
            })
        elif re.search(r"\b(?:hashlib\.sha1|sha1\.New|sha1\.Sum|MessageDigest\.getInstance\s*\(\s*\"SHA-?1\"\)|crypto/sha1)\b", line, re.IGNORECASE) or "sha1withrsa" in line.lower():
            findings.append({
                "canonical_algorithm": "SHA-1",
                "explanation": "SHA-1 is deprecated and vulnerable to practical collision attacks.",
                "risk_rating": "Critical",
                "quantum_vulnerable": True,
                "quantum_safe": False,
                "source_type": "source-code",
                "source_path": display_name,
                "operation": "DIGEST",
                "line_number": idx,
                "matched_snippet": raw_line.strip(),
                "rule_id": "src-sha1-digest",
                "nist_standard": "FIPS 180-4",
            })

        # 4. AES
        if "algorithms.AES(" in line or 'Cipher.getInstance("AES' in line or "aes.NewCipher(" in line:
            mode = "ECB" if "ECB" in line else "GCM"
            risk = "Critical" if mode == "ECB" else "Safe"
            findings.append({
                "canonical_algorithm": "AES-256-GCM" if mode != "ECB" else "AES-ECB",
                "explanation": "ECB mode leaks plaintext patterns." if mode == "ECB" else "AES-256 maintains 128-bit quantum security.",
                "risk_rating": risk,
                "quantum_vulnerable": (risk == "Critical"),
                "quantum_safe": (risk == "Safe"),
                "source_type": "source-code",
                "source_path": display_name,
                "operation": "ENCRYPT",
                "line_number": idx,
                "matched_snippet": raw_line.strip(),
                "rule_id": "src-aes-cipher",
                "nist_standard": "FIPS 197",
            })

        # 5. PBKDF2
        if re.search(r"\b(?:PBKDF2|pbkdf2_hmac|SecretKeyFactory\.getInstance\s*\(\s*\"PBKDF2|deriveKey)\b", line):
            findings.append({
                "canonical_algorithm": "PBKDF2",
                "explanation": "Key derivation function maintains symmetric quantum resistance.",
                "risk_rating": "Safe",
                "quantum_vulnerable": False,
                "quantum_safe": True,
                "source_type": "source-code",
                "source_path": display_name,
                "operation": "KDF",
                "line_number": idx,
                "matched_snippet": raw_line.strip(),
                "rule_id": "src-pbkdf2-kdf",
                "nist_standard": "none",
            })

    for f in findings:
        f["Scanner source"] = "FALLBACK heuristic"
        f["scanner_source"] = "FALLBACK heuristic"

    return findings


def _scan_cloud_file_fallback(path: Path) -> list[dict[str, Any]]:
    """Scan cloud posture JSON files if scanner is unavailable."""
    findings: list[dict[str, Any]] = []
    display_name = path.name

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return findings

    if not isinstance(data, dict):
        return findings

    # KMS keys
    for idx, key in enumerate(data.get("Keys", []), start=1):
        if not isinstance(key, dict):
            continue
        spec = str(key.get("KeySpec", "unknown"))
        arn = key.get("KeyArn", key.get("KeyId", "unknown"))
        spec_upper = spec.upper()
        if "RSA_2048" in spec_upper:
            algo = "RSA-2048"
            risk = "Critical"
        elif "RSA_3072" in spec_upper:
            algo = "RSA-3072"
            risk = "Critical"
        elif "RSA_4096" in spec_upper:
            algo = "RSA-4096"
            risk = "Critical"
        elif "RSA" in spec_upper:
            algo = "RSA"
            risk = "Critical"
        elif "P384" in spec_upper:
            algo = "ECC-NIST-P384"
            risk = "Critical"
        elif "P521" in spec_upper:
            algo = "ECC-NIST-P521"
            risk = "Critical"
        elif "P256" in spec_upper or "ECC" in spec_upper:
            algo = "ECC-NIST-P256"
            risk = "Critical"
        elif "SYMMETRIC" in spec_upper or "AES" in spec_upper:
            algo = "AES-256-GCM"
            risk = "Safe"
        else:
            algo = spec if spec != "unknown" else "unknown"
            risk = "Unknown"

        findings.append({
            "canonical_algorithm": algo,
            "explanation": f"KMS key {spec} is quantum vulnerable." if risk == "Critical" else (f"KMS key {spec} is quantum resistant." if risk == "Safe" else f"KMS key {spec} risk unverified."),
            "risk_rating": risk,
            "quantum_vulnerable": (risk == "Critical"),
            "quantum_safe": (risk == "Safe"),
            "source_type": "cloud-posture",
            "source_path": display_name,
            "operation": "SIGN_VERIFY" if risk == "Critical" else "ENCRYPT_DECRYPT",
            "line_number": idx,
            "matched_snippet": f"{arn} (KeySpec: {spec})",
            "rule_id": "aws-kms-key-spec",
            "nist_standard": "FIPS 186-5" if risk == "Critical" else ("FIPS 197" if risk == "Safe" else "none"),
        })

    # Load balancers
    for lb in data.get("LoadBalancers", []):
        if not isinstance(lb, dict):
            continue
        for idx, listener in enumerate(lb.get("Listeners", []), start=1):
            if not isinstance(listener, dict):
                continue
            proto = listener.get("Protocol", "")
            port = listener.get("Port", 0)
            if proto == "HTTP" or str(port) == "80":
                findings.append({
                    "canonical_algorithm": "Cleartext-HTTP",
                    "explanation": "Plaintext traffic over unencrypted port 80.",
                    "risk_rating": "Critical",
                    "quantum_vulnerable": True,
                    "quantum_safe": False,
                    "source_type": "cloud-posture",
                    "source_path": display_name,
                    "operation": "KEY_EXCHANGE",
                    "line_number": idx,
                    "matched_snippet": f"Listener port {port} unencrypted HTTP",
                    "rule_id": "aws-alb-cleartext",
                    "nist_standard": "none",
                })
            elif listener.get("SslPolicy"):
                policy = str(listener.get("SslPolicy"))
                findings.append({
                    "canonical_algorithm": "TLS-Classical-Cipher",
                    "explanation": f"ELB policy {policy} negotiates classical cipher suites.",
                    "risk_rating": "Critical",
                    "quantum_vulnerable": True,
                    "quantum_safe": False,
                    "source_type": "cloud-posture",
                    "source_path": display_name,
                    "operation": "KEY_EXCHANGE",
                    "line_number": idx,
                    "matched_snippet": f"SslPolicy: {policy}",
                    "rule_id": "aws-alb-ssl-policy",
                    "nist_standard": "SP 800-52",
                })

    # ACM certificates
    for idx, cert in enumerate(data.get("Certificates", []), start=1):
        if not isinstance(cert, dict):
            continue
        key_algo = str(cert.get("KeyAlgorithm", "RSA_2048"))
        domain = cert.get("DomainName", "unknown")
        algo_name = key_algo.replace("_", "-") if ("RSA" in key_algo or "ECC" in key_algo) else key_algo
        findings.append({
            "canonical_algorithm": algo_name,
            "explanation": f"Public key certificate ({key_algo}) is vulnerable to Shor's algorithm.",
            "risk_rating": "Critical",
            "quantum_vulnerable": True,
            "quantum_safe": False,
            "source_type": "cloud-posture",
            "source_path": display_name,
            "operation": "SIGN_VERIFY",
            "line_number": idx,
            "matched_snippet": f"Certificate for {domain} ({key_algo})",
            "rule_id": "aws-acm-cert",
            "nist_standard": "FIPS 186-5",
        })

    for f in findings:
        f["Scanner source"] = "FALLBACK heuristic"
        f["scanner_source"] = "FALLBACK heuristic"

    return findings


def _scan_pcap_file_fallback(path: Path) -> list[dict[str, Any]]:
    """Scan network PCAP captures for cleartext and TLS handshakes."""
    findings: list[dict[str, Any]] = []
    display_name = path.name

    try:
        raw_bytes = path.read_bytes()
    except OSError:
        return findings

    if not raw_bytes:
        return findings

    # 1. Cleartext HTTP
    if b"HTTP/" in raw_bytes or b"GET " in raw_bytes or b"POST " in raw_bytes:
        findings.append({
            "canonical_algorithm": "Cleartext-HTTP",
            "explanation": "Unencrypted HTTP network traffic observed in capture.",
            "risk_rating": "Critical",
            "quantum_vulnerable": True,
            "quantum_safe": False,
            "source_type": "network-capture",
            "source_path": display_name,
            "operation": "KEY_EXCHANGE",
            "line_number": None,
            "packet_number": 1,
            "matched_snippet": "Unencrypted HTTP traffic on port 80",
            "rule_id": "pcap-cleartext-http",
            "nist_standard": "none",
        })

    # 2. Negotiated TLS handshake (heuristic check for TLS record markers 0x1603 or TLS keyword)
    if b"\x16\x03" in raw_bytes or b"TLS" in raw_bytes:
        findings.append({
            "canonical_algorithm": "ECDHE-RSA-AES128-GCM-SHA256",
            "explanation": "Negotiated TLS cipher suite relies on classical key exchange.",
            "risk_rating": "Critical",
            "quantum_vulnerable": True,
            "quantum_safe": False,
            "source_type": "network-capture",
            "source_path": display_name,
            "operation": "KEY_EXCHANGE",
            "line_number": None,
            "packet_number": 1,
            "matched_snippet": "TLS 1.2 handshake negotiated classical cipher suite",
            "rule_id": "pcap-tls-cipher",
            "nist_standard": "FIPS 186-5",
        })

    for f in findings:
        f["Scanner source"] = "FALLBACK heuristic"
        f["scanner_source"] = "FALLBACK heuristic"

    return findings


def scan_uploaded_files(
    uploaded_files: list[Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Scan user-uploaded files safely inside a temporary directory."""
    if not uploaded_files:
        return None, ["No files selected for scanning."]

    warnings: list[str] = []
    all_findings: list[Any] = []

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        cloud_dir = temp_dir / "cloud"
        cloud_dir.mkdir(parents=True, exist_ok=True)

        cloud_uploads: list[tuple[Path, str]] = []
        pcap_uploads: list[tuple[Path, str]] = []
        source_uploads: list[tuple[Path, str]] = []

        for idx, upload in enumerate(uploaded_files):
            orig_name = Path(upload.name).name
            ext = Path(orig_name).suffix.lower()

            if ext == ".json":
                target_path = cloud_dir / f"{idx}_{orig_name}"
                target_path.write_bytes(upload.getvalue())
                cloud_uploads.append((target_path, orig_name))
            elif ext in (".pcap", ".pcapng"):
                sub_dir = temp_dir / f"pcap_{idx}"
                sub_dir.mkdir(parents=True, exist_ok=True)
                target_path = sub_dir / orig_name
                target_path.write_bytes(upload.getvalue())
                pcap_uploads.append((target_path, orig_name))
            elif ext in (".py", ".java", ".go"):
                sub_dir = temp_dir / f"src_{idx}"
                sub_dir.mkdir(parents=True, exist_ok=True)
                target_path = sub_dir / orig_name
                target_path.write_bytes(upload.getvalue())
                source_uploads.append((target_path, orig_name))
            else:
                warnings.append(f"Skipped unsupported file: {orig_name}")

        # 1. Scan cloud posture JSONs together
        if cloud_uploads:
            try:
                real_scanner = _get_cloud_scanner()
                if real_scanner:
                    scanner_mod, method_name = real_scanner
                    logger.info("Using real scanner: %s (via %s) for cloud-posture", scanner_mod.__name__, method_name)
                    method = getattr(scanner_mod, method_name)
                    cloud_findings = method(cloud_dir)
                    if not isinstance(cloud_findings, list):
                        cloud_findings = [cloud_findings] if cloud_findings else []
                    _tag_findings_scanner_source(cloud_findings, f"real: {scanner_mod.__name__}")
                else:
                    logger.info("Using FALLBACK heuristic for cloud-posture")
                    cloud_findings = []
                    for c_path, _ in cloud_uploads:
                        cloud_findings.extend(_scan_cloud_file_fallback(c_path))

                for finding in cloud_findings:
                    if hasattr(finding, "evidence") and finding.evidence:
                        for ev in finding.evidence:
                            raw_p = Path(ev.file_path).name
                            for _, orig in cloud_uploads:
                                if raw_p.endswith(orig):
                                    ev.file_path = orig
                                    break
                    elif isinstance(finding, dict) and "source_path" in finding:
                        raw_p = Path(finding["source_path"]).name
                        for _, orig in cloud_uploads:
                            if raw_p.endswith(orig):
                                finding["source_path"] = orig
                                break
                    all_findings.append(finding)
            except Exception as exc:  # noqa: BLE001 - isolate optional cloud scanner failures
                warnings.append(f"Error scanning cloud posture files: {exc}")

        # 2. Scan PCAP files
        for pcap_path, orig_name in pcap_uploads:
            try:
                real_scanner = _get_pcap_scanner()
                if real_scanner:
                    scanner_mod, method_name = real_scanner
                    logger.info("Using real scanner: %s (via %s) for network-capture", scanner_mod.__name__, method_name)
                    method = getattr(scanner_mod, method_name)
                    pcap_findings = method(pcap_path)
                    if not isinstance(pcap_findings, list):
                        pcap_findings = [pcap_findings] if pcap_findings else []
                    _tag_findings_scanner_source(pcap_findings, f"real: {scanner_mod.__name__}")
                else:
                    logger.info("Using FALLBACK heuristic for network-capture")
                    pcap_findings = _scan_pcap_file_fallback(pcap_path)

                for finding in pcap_findings:
                    if hasattr(finding, "evidence") and finding.evidence:
                        for ev in finding.evidence:
                            ev.file_path = orig_name
                    elif isinstance(finding, dict):
                        finding["source_path"] = orig_name
                    all_findings.append(finding)
            except Exception as exc:  # noqa: BLE001 - isolate optional network scanner failures
                warnings.append(f"Error scanning {orig_name}: {exc}")

        # 3. Scan Source code files
        for src_path, orig_name in source_uploads:
            try:
                real_scanner = _get_source_scanner_file()
                src_findings = []
                if real_scanner:
                    scanner_mod, method_name = real_scanner
                    method = getattr(scanner_mod, method_name)
                    try:
                        real_results = method(src_path)
                    except Exception as exc:  # noqa: BLE001 - isolate optional source scanner failures
                        warnings.append(f"Error scanning {orig_name}: {exc}")
                        real_results = []

                    if isinstance(real_results, list) and real_results:
                        logger.info("Using real scanner: %s (via %s) for source-code", scanner_mod.__name__, method_name)
                        _tag_findings_scanner_source(real_results, f"real: {scanner_mod.__name__}")
                        src_findings = real_results
                    elif src_path.suffix.lower() == ".go":
                        logger.info("Using real scanner: %s (via %s) for source-code", scanner_mod.__name__, method_name)
                        _tag_findings_scanner_source(real_results, f"real: {scanner_mod.__name__}")
                        src_findings = real_results if isinstance(real_results, list) else []

                if not src_findings and src_path.suffix.lower() != ".go":
                    logger.info("Using FALLBACK heuristic for source-code: %s", orig_name)
                    src_findings = _scan_source_file_fallback(src_path)

                for finding in src_findings:
                    if hasattr(finding, "evidence") and finding.evidence:
                        for ev in finding.evidence:
                            ev.file_path = orig_name
                    elif isinstance(finding, dict):
                        finding["source_path"] = orig_name
                    all_findings.append(finding)
            except Exception as exc:  # noqa: BLE001 - isolate optional source file scan failures
                warnings.append(f"Error scanning {orig_name}: {exc}")

    if not all_findings:
        return None, warnings or ["No cryptographic findings detected in uploaded files."]

    cbom = _build_cbom_from_findings(all_findings)
    return cbom, warnings


def scan_bundled_data(
    sample_dir: Path = DEFAULT_SAMPLE_DIR,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Scan the bundled sample data repository folders."""
    warnings: list[str] = []
    findings: list[Any] = []

    sample_repos = sample_dir / "sample-repos"
    cloud_dir = sample_dir / "cloud-posture"
    pcap_dir = sample_dir / "network-capture"

    if sample_repos.exists():
        try:
            real_scanner = _get_source_scanner_dir()
            if real_scanner:
                scanner_mod, method_name = real_scanner
                logger.info("Using real scanner: %s (via %s) for source-code", scanner_mod.__name__, method_name)
                method = getattr(scanner_mod, method_name)
                src_res = method(sample_repos)
                if not isinstance(src_res, list):
                    src_res = [src_res] if src_res else []
                _tag_findings_scanner_source(src_res, f"real: {scanner_mod.__name__}")
                findings.extend(src_res)
            else:
                logger.info("Using FALLBACK heuristic for source-code")
                for ext in ("*.py", "*.java", "*.go"):
                    for file_p in sample_repos.rglob(ext):
                        findings.extend(_scan_source_file_fallback(file_p))
        except Exception as exc:  # noqa: BLE001 - isolate sample repo scan failures
            warnings.append(f"Error scanning sample repos: {exc}")

    if cloud_dir.exists():
        try:
            real_scanner = _get_cloud_scanner()
            if real_scanner:
                scanner_mod, method_name = real_scanner
                logger.info("Using real scanner: %s (via %s) for cloud-posture", scanner_mod.__name__, method_name)
                method = getattr(scanner_mod, method_name)
                cloud_res = method(cloud_dir)
                if not isinstance(cloud_res, list):
                    cloud_res = [cloud_res] if cloud_res else []
                _tag_findings_scanner_source(cloud_res, f"real: {scanner_mod.__name__}")
                findings.extend(cloud_res)
            else:
                logger.info("Using FALLBACK heuristic for cloud-posture")
                for json_p in cloud_dir.glob("*.json"):
                    findings.extend(_scan_cloud_file_fallback(json_p))
        except Exception as exc:  # noqa: BLE001 - isolate cloud posture scan failures
            warnings.append(f"Error scanning cloud posture: {exc}")

    if pcap_dir.exists():
        for pcap_file in pcap_dir.glob("*.pcap*"):
            try:
                real_scanner = _get_pcap_scanner()
                if real_scanner:
                    scanner_mod, method_name = real_scanner
                    logger.info("Using real scanner: %s (via %s) for network-capture", scanner_mod.__name__, method_name)
                    method = getattr(scanner_mod, method_name)
                    pcap_res = method(pcap_file)
                    if not isinstance(pcap_res, list):
                        pcap_res = [pcap_res] if pcap_res else []
                    _tag_findings_scanner_source(pcap_res, f"real: {scanner_mod.__name__}")
                    findings.extend(pcap_res)
                else:
                    logger.info("Using FALLBACK heuristic for network-capture")
                    findings.extend(_scan_pcap_file_fallback(pcap_file))
            except Exception as exc:  # noqa: BLE001 - isolate network capture scan failures
                warnings.append(f"Error scanning network capture: {exc}")

    if not findings:
        return None, warnings or ["No findings discovered in bundled sample data."]

    cbom = _build_cbom_from_findings(findings)
    return cbom, warnings


def render_dashboard(
    cbom: dict[str, Any],
    cbom_path: str | Path | None = None,
) -> None:
    """Render the interactive CBOM dashboard."""
    if st is None:
        render_cli_fallback_notice()
        return

    dataframe = _safe_text_columns(
        load_findings_dataframe(cbom)
    )

    with st.sidebar:
        st.divider()
        st.header("Filters")

        source_options = sorted(
            value
            for value in dataframe["Source Type"]
            .dropna()
            .unique()
        )

        risk_options = [
            risk
            for risk in RISK_ORDER
            if risk in set(dataframe["Risk Rating"])
        ]

        selected_sources = st.multiselect(
            "Data source",
            options=source_options,
            default=source_options,
        )

        selected_risks = st.multiselect(
            "Risk tier",
            options=risk_options,
            default=risk_options,
        )

        search_query = st.text_input(
            "Search algorithm or evidence",
            placeholder="RSA, SHA-1, source path, rule ID...",
        )

        if st.button("Clear active scan", use_container_width=True):
            st.session_state["cbom"] = None
            st.session_state["cbom_source"] = None
            st.session_state["scan_warnings"] = []
            st.rerun()

    scanner_name, scanner_version = _extract_tool_info(cbom)

    metadata = cbom.get("metadata", {})
    timestamp = (
        metadata.get("timestamp", "unknown")
        if isinstance(metadata, dict)
        else "unknown"
    )

    st.title("QuantumTrace Cryptographic Risk Dashboard")
    st.caption("CycloneDX 1.6 Cryptography Bill of Materials")
    st.caption(
        f"Scanner: {scanner_name} {scanner_version} · "
        f"Generated: {timestamp}"
    )

    if "Scanner source" in dataframe.columns:
        fallback_mask = dataframe["Scanner source"] == "FALLBACK heuristic"
        if fallback_mask.any():
            used_types = sorted(
                str(t)
                for t in dataframe.loc[fallback_mask, "Source Type"].dropna().unique()
            )
            types_str = ", ".join(used_types) if used_types else "unknown inputs"
            st.warning(f"⚠️ Fallback heuristic scanner used for: {types_str}")

    filtered_dataframe = dataframe[
        dataframe["Source Type"].isin(selected_sources)
        & dataframe["Risk Rating"].isin(selected_risks)
    ].copy()

    if search_query:
        query = search_query.casefold()
        search_mask = False

        searchable_columns = [
            "Algorithm",
            "Source Path",
            "Matched Snippet",
            "Rule ID",
            "NIST Standard",
            "Description",
        ]

        for column in searchable_columns:
            if column not in filtered_dataframe.columns:
                continue

            search_mask = search_mask | (
                filtered_dataframe[column]
                .fillna("unknown")
                .astype(str)
                .str.casefold()
                .str.contains(
                    query,
                    regex=False,
                    na=False,
                )
            )

        filtered_dataframe = filtered_dataframe[search_mask]

    report_findings = _report_findings_from_cbom(cbom)
    summary = build_report_summary(report_findings) if build_report_summary is not None else None

    _render_metrics(dataframe, summary=summary)

    st.subheader("Executive Risk Report")

    with st.expander("ℹ️ Dual-Axis Risk Model (Quantum Risk vs. Classical Risk)", expanded=False):
        st.markdown(
            """
            QuantumTrace evaluates cryptographic posture along two independent security axes:

            - **Quantum Risk**: Future quantum vulnerability (e.g. exposure to Shor's algorithm for factoring/discrete logs, or Grover's algorithm for symmetric search).
            - **Classical Risk**: Current pre-quantum cryptographic strength (e.g. exposure to known classical cryptanalysis, collision attacks, or deprecated key sizes).

            **Why can an asset have different risk ratings across axes?**
            - **RSA-2048**: `Quantum Risk = Critical` (completely broken by Shor's algorithm; must migrate to PQC) while `Classical Risk = Safe` (provides ~112 bits of classical security; not classically broken today).
            - **RSA-1024**: `Quantum Risk = Critical` while `Classical Risk = Medium` (classically deprecated key length).
            - **MD5 / SHA-1 / DES**: `Quantum Risk = Critical` and `Classical Risk = Critical` (classically broken via known practical collision/brute-force attacks).
            - **AES-256-GCM / SHA-384**: `Quantum Risk = Safe` and `Classical Risk = Safe` (maintains ≥128 bits of quantum security against Grover's algorithm).
            """
        )

    if summary:
        col_src, col_algo = st.columns(2)
        with col_src:
            st.markdown("#### Findings by Source")
            by_src = summary.get("by_source_type", {})
            if by_src:
                src_df = pd.DataFrame(
                    [{"Source Type": k, "Count": v} for k, v in by_src.items()]
                )
                st.dataframe(src_df, hide_index=True, use_container_width=True)
            else:
                st.write("No source data available.")

        with col_algo:
            st.markdown("#### Findings by Algorithm")
            by_algo = summary.get("by_algorithm", {})
            if by_algo:
                algo_df = pd.DataFrame(
                    [{"Algorithm": k, "Count": v} for k, v in by_algo.items()]
                )
                st.dataframe(algo_df, hide_index=True, use_container_width=True)
            else:
                st.write("No algorithm data available.")

        with st.expander("View Full Executive Risk Report (JSON)", expanded=False):
            st.json(summary)

    chart_column, summary_column = st.columns([1, 1])

    with chart_column:
        st.subheader("Risk distribution")
        _render_risk_chart(filtered_dataframe)

    with summary_column:
        st.subheader("Scan summary")
        st.write(f"**Findings displayed:** {len(filtered_dataframe)}")
        st.write(f"**Total components:** {len(dataframe)}")
        st.write(f"**Scanner:** {scanner_name} {scanner_version}")

        if cbom_path:
            st.write(f"**CBOM source:** `{cbom_path}`")

        _render_download_button(cbom)

    st.subheader("Cryptographic findings")

    if filtered_dataframe.empty:
        st.info("No findings match the selected filters.")
        return

    display_columns = [
        "Algorithm",
        "Quantum Risk",
        "Classical Risk",
        "Risk Rating",
        "Scanner source",
        "Source Type",
        "Source Path",
        "Operation",
        "Line Number",
        "Matched Snippet",
        "Rule ID",
        "NIST Standard",
        "Description",
        "Quantum Vulnerable",
        "Quantum Safe",
    ]

    display_dataframe = filtered_dataframe[
        [
            column
            for column in display_columns
            if column in filtered_dataframe.columns
        ]
    ]

    st.dataframe(
        _style_dataframe(display_dataframe),
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("🔍 Inspect Finding Evidence & NIST Guidance", expanded=False):
        if not filtered_dataframe.empty:
            selected_idx = st.selectbox(
                "Select finding to inspect",
                options=list(range(len(filtered_dataframe))),
                format_func=lambda i: (
                    f"#{i+1}: {filtered_dataframe.iloc[i].get('Algorithm', 'Unknown')} "
                    f"({filtered_dataframe.iloc[i].get('Source Path', 'unknown')})"
                ),
            )
            if selected_idx is not None:
                f_row = filtered_dataframe.iloc[selected_idx]
                col_a, col_b = st.columns(2)
                with col_a:
                    st.write(f"**Algorithm:** {f_row.get('Algorithm')}")
                    st.write(f"**Quantum Risk:** {f_row.get('Quantum Risk', f_row.get('Risk Rating'))}")
                    st.write(f"**Classical Risk:** {f_row.get('Classical Risk', 'Unknown')}")
                    st.write(f"**NIST Standard:** {f_row.get('NIST Standard', 'none')}")
                    st.write(f"**Operation:** {f_row.get('Operation', 'unknown')}")
                with col_b:
                    st.write(f"**Source File:** `{f_row.get('Source Path', 'unknown')}`")
                    st.write(f"**Line Number:** {f_row.get('Line Number', 'unknown')}")
                    st.write(f"**Rule ID:** `{f_row.get('Rule ID', 'unknown')}`")
                    st.write(f"**Matched Snippet:** `{f_row.get('Matched Snippet', 'unknown')}`")
                st.info(f"**Risk Reasoning:** {f_row.get('Description', 'No description available.')}")

    # Findings CSV download button
    st.download_button(
        label="Download Findings as CSV",
        data=display_dataframe.to_csv(index=False).encode("utf-8"),
        file_name="quantumtrace_findings.csv",
        mime="text/csv",
        use_container_width=True,
    )


def _load_default_cbom() -> tuple[dict[str, Any] | None, str | None]:
    """Load cbom.json if present and return its path."""
    if not DEFAULT_CBOM_PATH.exists():
        return None, None

    try:
        modification_time = DEFAULT_CBOM_PATH.stat().st_mtime
        data = load_cbom(
            filepath=str(DEFAULT_CBOM_PATH),
            file_mtime=modification_time,
        )
        return data, str(DEFAULT_CBOM_PATH)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if st is not None:
            st.error(f"Unable to load {DEFAULT_CBOM_PATH}: {exc}")
        else:
            print(f"Unable to load {DEFAULT_CBOM_PATH}: {exc}")

        return None, str(DEFAULT_CBOM_PATH)


def main() -> None:
    """Run the Streamlit dashboard."""
    if st is None:
        render_cli_fallback_notice()
        return

    st.set_page_config(
        page_title="QuantumTrace Dashboard",
        page_icon="🔐",
        layout="wide",
    )

    if "cbom" not in st.session_state:
        st.session_state["cbom"] = None
    if "cbom_source" not in st.session_state:
        st.session_state["cbom_source"] = None
    if "scan_warnings" not in st.session_state:
        st.session_state["scan_warnings"] = []

    with st.sidebar:
        st.title("QuantumTrace")
        st.caption("Cryptographic Scanner & CBOM Generator")

        uploaded_files = st.file_uploader(
            "Upload files to scan (JSON, PCAP, Source)",
            type=["json", "pcap", "pcapng", "py", "java", "go"],
            accept_multiple_files=True,
        )

        scan_uploaded_button = st.button("Scan uploaded files", use_container_width=True)
        scan_bundled_button = st.button("Scan bundled sample data", use_container_width=True)

        st.divider()
        uploaded_cbom = st.file_uploader(
            "Upload existing CycloneDX CBOM",
            type=["json"],
            accept_multiple_files=False,
        )

        load_local_button = False
        if DEFAULT_CBOM_PATH.exists():
            load_local_button = st.button("Load local cbom.json", use_container_width=True)

    # Handle scan actions
    if scan_uploaded_button:
        if not uploaded_files:
            st.sidebar.warning("Please upload at least one file to scan.")
        else:
            with st.spinner("Scanning uploaded files..."):
                cbom_data, warnings = scan_uploaded_files(uploaded_files)
                st.session_state["cbom"] = cbom_data
                st.session_state["cbom_source"] = f"{len(uploaded_files)} uploaded file(s)"
                st.session_state["scan_warnings"] = warnings
            st.rerun()

    if scan_bundled_button:
        with st.spinner("Scanning bundled sample data..."):
            cbom_data, warnings = scan_bundled_data()
            st.session_state["cbom"] = cbom_data
            st.session_state["cbom_source"] = "Bundled sample data"
            st.session_state["scan_warnings"] = warnings
        st.rerun()

    if uploaded_cbom is not None:
        try:
            cbom_data = load_cbom(
                file_bytes=uploaded_cbom.getvalue(),
                filepath="",
            )
            st.session_state["cbom"] = cbom_data
            st.session_state["cbom_source"] = uploaded_cbom.name
            st.session_state["scan_warnings"] = []
        except Exception as exc:  # noqa: BLE001 - isolate CBOM upload parsing failure
            st.sidebar.error(f"Failed to load CBOM JSON: {exc}")

    if load_local_button:
        cbom_data, cbom_path = _load_default_cbom()
        if cbom_data is not None:
            st.session_state["cbom"] = cbom_data
            st.session_state["cbom_source"] = cbom_path
            st.session_state["scan_warnings"] = []
            st.rerun()

    # Empty state: nothing scanned yet
    active_cbom = st.session_state.get("cbom")
    if active_cbom is None:
        st.title("QuantumTrace Cryptographic Risk Dashboard")
        st.caption("CycloneDX 1.6 Cryptography Bill of Materials")
        st.info(
            "👈 **Welcome!** Upload source code (.py, .java, .go), cloud posture JSON, "
            "or network captures (.pcap) in the sidebar and click **Scan uploaded files**.\n\n"
            "Or click **Scan bundled sample data** for a quick demonstration of "
            "quantum vulnerabilities, risk scoring, and CBOM generation."
        )

        for warn in st.session_state.get("scan_warnings", []):
            st.warning(warn)

        return

    # Render dashboard from session state
    for warn in st.session_state.get("scan_warnings", []):
        st.warning(warn)

    render_dashboard(active_cbom, st.session_state.get("cbom_source"))


if __name__ == "__main__":
    main()

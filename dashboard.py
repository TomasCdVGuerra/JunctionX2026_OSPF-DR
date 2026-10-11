"""Streamlit dashboard for QuantumTrace CycloneDX 1.6 CBOM reports."""

from __future__ import annotations

import json
import hashlib
import importlib
import logging
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from scanner.models import CryptoFinding
from scanner.dashboard_fallbacks import (
    scan_source_file as _scan_source_file_fallback,
    scan_cloud_file as _scan_cloud_file_fallback,
    scan_pcap_file as _scan_pcap_file_fallback,
)
from scanner.risk import enrich_finding
from scanner.nist_references import collect_nist_references
from scanner.presentation import risk_details
from scanner.report import summarize_scan_coverage

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
    from scanner.report import build_report_summary, calculate_hygiene_score, calculate_posture_status
except ImportError:  # pragma: no cover
    calculate_hygiene_score = None  # type: ignore[assignment]
    calculate_posture_status = None  # type: ignore[assignment]


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
        for method_name in ("scan_json_file", "scan"):
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
        for method_name in ("scan_file", "scan_source_file", "scan"):
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
    properties = _extract_properties(component.get("properties", []))
    stored = properties.get("cryptotrace:evidence")
    if stored:
        try:
            items = json.loads(stored)
        except (ValueError, TypeError):
            items = []
        if isinstance(items, list):
            sources = [item for item in items if isinstance(item, dict)
                       and item.get("rule_id") != "RISK-ENGINE-ASSESSMENT"]
            if sources:
                first = sources[0]
                standard = collect_nist_references(items)
                return {
                    "Source Path": _normalise(first.get("file_path")),
                    "Line Number": _normalise(first.get("line_number"), "N/A"),
                    "JSON Path": _normalise(first.get("json_path"), "N/A"),
                    "Packet Number": _normalise(first.get("packet_number"), "N/A"),
                    "Matched Snippet": _normalise(first.get("matched_snippet")),
                    "Rule ID": _normalise(first.get("rule_id")),
                    "NIST References": _normalise(standard),
                }
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
        "NIST References": _normalise(
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

    risk_rating = risk_rating.capitalize()

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

    row = {
        "Algorithm": _normalise(component.get("name")),
        "Quantum Risk": risk_rating,
        "Classical Risk": properties.get("cryptotrace:classical_risk", properties.get("cryptotrace:classicalRisk", "unknown")).capitalize(),
        "Recommendation": property_value("cryptotrace:recommendation"),
        "Observation": property_value("cryptotrace:observation"),
        "Scanner source": scanner_source,
        "Source Type": source_type,
        "Source Path": source_path,
        "Input ID": property_value("cryptotrace:scan_input_id"),
        "Operation": operation,
        "Library / API": properties.get("cryptotrace:library", "N/A"),
        "Quantum Vulnerable": property_value(
            "cryptotrace:quantumVulnerable"
        ),
        "Quantum Safe": property_value(
            "cryptotrace:quantumSafe"
        ),
        "Line Number": evidence.get("Line Number", "unknown"),
        "JSON Path": evidence.get("JSON Path", "N/A"),
        "Packet Number": evidence.get("Packet Number", "N/A"),
        "Matched Snippet": evidence.get(
            "Matched Snippet",
            "unknown",
        ),
        "Rule ID": evidence.get("Rule ID", "unknown"),
        "NIST References": (
            evidence.get("NIST References", "unknown")
            if evidence.get("NIST References", "unknown") != "unknown"
            else properties.get("cryptotrace:nistStandard", "unknown")
        ),
        "BOM Reference": _normalise(component.get("bom-ref")),
        "Description": _normalise(component.get("description")),
    }

    for key, value in native_properties.items():
        row[f"Crypto: {key}"] = value

    for key, value in properties.items():
        if key.startswith("cryptotrace:") and key not in {
            "cryptotrace:riskRating",
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
            c_func = getattr(component, "crypto_function", None)
            rows.append({
                "Algorithm": _normalise(getattr(component, "algorithm_name", None)),
                "Classical Risk": _normalise(getattr(component, "classical_risk", None)).capitalize(),
                "Recommendation": _normalise(getattr(component, "recommendation", None)),
                "Observation": _normalise(getattr(component, "observation", None)),
                "Quantum Risk": (
                    q_risk.value if q_risk is not None and hasattr(q_risk, "value") else str(q_risk or "unknown")
                ).capitalize(),
                "Scanner source": "unknown",
                "Source Type": _normalise(getattr(component, "source_type", None)),
                "Source Path": getattr(first_ev, "file_path", "unknown") if first_ev else "unknown",
                "Operation": (
                    c_func.value if c_func is not None and hasattr(c_func, "value") else str(c_func or "unknown")
                ),
                "Quantum Vulnerable": "true" if getattr(q_risk, "value", q_risk) == "critical" else "false",
                "Quantum Safe": "true" if getattr(q_risk, "value", q_risk) == "safe" else "false",
                "Line Number": str(getattr(first_ev, "line_number", "unknown")),
                "JSON Path": _normalise(getattr(first_ev, "json_path", None), "N/A"),
                "Packet Number": _normalise(getattr(first_ev, "packet_number", None), "N/A"),
                "Matched Snippet": _normalise(getattr(first_ev, "matched_snippet", None)),
                "Rule ID": _normalise(getattr(first_ev, "rule_id", None)),
                "NIST References": _normalise(collect_nist_references(ev_list)),
                "BOM Reference": "unknown",
                "Description": _normalise(CBOMSerializer._finding_value(component, "explanation") if CBOMSerializer else getattr(first_ev, "risk_reasoning", None)),
            })

    columns = [
        "Algorithm",
        "Classical Risk",
        "Recommendation",
        "Observation",
        "Quantum Risk",
        "Scanner source",
        "Source Type",
        "Source Path",
        "Input ID",
        "Operation",
        "Quantum Vulnerable",
        "Quantum Safe",
        "Line Number",
        "Matched Snippet",
        "Rule ID",
        "NIST References",
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

    return style_function(_risk_css, subset=[column for column in
                                          ("Quantum Risk", "Classical Risk") if column in dataframe.columns])


def _finding_location(row) -> str:
    """Use the location appropriate to this observation, without inventing offsets."""
    for field, prefix in (("Line Number", "Line "), ("Packet Number", "Packet "), ("JSON Path", "")):
        value = str(row.get(field, "N/A"))
        if value.strip().lower() not in {"", "unknown", "n/a", "none", "nan"}:
            return prefix + value
    return "N/A"


def _compact_findings_dataframe(dataframe):
    overview = dataframe[["Algorithm", "Quantum Risk", "Classical Risk", "Source Path", "Observation"]].copy()
    overview.insert(4, "Location", dataframe.apply(_finding_location, axis=1))
    if "Input ID" in dataframe:
        overview["Source Path"] = dataframe.apply(_finding_source_label, axis=1)
    return overview.rename(columns={"Source Path": "Source"})


def _finding_source_label(row) -> str:
    input_id = str(row.get("Input ID", "unknown"))
    path = str(row.get("Source Path", "unknown"))
    return f"#{input_id} {path}" if input_id.isdigit() else path


def _render_finding_details(row, cbom: dict[str, Any]) -> None:
    """Explain one selected observation; preserve its entire record for inspection."""
    st.subheader("Finding details")
    st.write(f"**Algorithm:** {row['Algorithm']}")
    st.caption(f"{row['Source Type']} · {_finding_source_label(row)} · {_finding_location(row)}")
    st.write(f"**Operation:** {row.get('Operation', 'unknown')} · **Library / API:** {row.get('Library / API', 'N/A')}")
    size = row.get("cryptotrace:key_size")
    mode = row.get("cryptotrace:mode", row.get("Crypto: mode"))
    parameters = []
    if size and str(size).lower() not in {"unknown", "n/a", "nan", "none"}:
        parameters.append(f"Key size: {size} bits")
    if mode and str(mode).lower() not in {"unknown", "n/a", "nan", "none"}:
        parameters.append(f"Mode: {mode}")
    if parameters:
        st.caption(" · ".join(parameters))
    observation_help = {
        "declared": "Found in source code; this does not prove runtime use.",
        "configured": "Present in configuration; this does not prove traffic used it.",
        "advertised": "An offered capability; it may not have been selected.",
        "negotiated": "A selected or inferred selection; this does not prove session completion.",
        "observed": "Direct evidence recorded by the scanner; interpret it within the source context.",
    }
    st.write(f"**Observation:** {row['Observation']}")
    explanation = observation_help.get(str(row["Observation"]).lower())
    if explanation:
        st.caption(explanation)
    details = risk_details(str(row.get("Description", "Unknown")),
                           str(row["Quantum Risk"]), str(row["Classical Risk"]),
                           algorithm=str(row["Algorithm"]))
    assessment_columns = st.columns(2)
    for column, axis, tier in zip(assessment_columns, ("Quantum", "Classical"),
                                  (row["Quantum Risk"], row["Classical Risk"])):
        with column:
            st.markdown(f"**{axis} Risk · {str(tier).upper()}**")
            st.caption(details[axis]["criterion"])
            st.write("**Why this rating**")
            displayed_reasons = details[axis]["reasons"]
            for reason in displayed_reasons:
                st.write("• " + reason)
            if str(tier).lower() == "unknown":
                st.write("**What remains unresolved**")
                for missing in details[axis]["missing"]:
                    st.write("• " + missing)
                if not details[axis]["missing"]:
                    st.caption("The record does not identify the missing parameters; inspect the complete evidence.")
            if details[axis]["known_concerns"]:
                st.warning("Known review items remain despite the incomplete assessment.")
                for concern in details[axis]["known_concerns"]:
                    st.write("• " + concern)
    st.write("**Recommended action**")
    st.write(row.get("Recommendation", "Unknown"))
    st.write("**Evidence**")
    st.caption(f"Check {row['Source Path']} at {_finding_location(row)}. Extraction rule: {row.get('Rule ID', 'unknown')}.")
    st.caption("The source establishes the algorithm and recorded parameters. The risk engine applies security rules; the source does not demonstrate an attack.")
    snippet = str(row.get("Matched Snippet", "unknown"))
    if snippet.lower() not in {"unknown", "n/a", "none", ""}:
        focused_evidence = _focused_cloud_evidence(row, snippet)
        if focused_evidence:
            st.write("**Field used for this finding**")
            st.code(json.dumps(focused_evidence, ensure_ascii=False, indent=2), language="json", wrap_lines=True)
            if "SignatureAlgorithm" in focused_evidence:
                st.caption("SignatureAlgorithm identifies the certificate signature. KeyAlgorithm describes the subject's key; it does not establish the issuer's signing-key size.")
            with st.expander("Original resource evidence"):
                st.code(snippet, language="json", wrap_lines=True)
        else:
            st.code(snippet, language=None, wrap_lines=True)
    else:
        st.caption("No snippet available; consult the recorded location and technical details.")
    st.write(f"**NIST references:** {row.get('NIST References', 'Unknown')}")
    st.caption("References are guidance, not certification.")
    with st.expander("Technical details and complete record"):
        st.json(row.to_dict() if hasattr(row, "to_dict") else dict(row))
        reference = row.get("BOM Reference")
        component = next((component for component in cbom.get("components", [])
                          if isinstance(component, dict) and component.get("bom-ref") == reference), None)
        if component:
            st.json(component)


def _focused_cloud_evidence(row, snippet: str) -> dict | None:
    """Highlight an exact field present in the recorded resource, never fabricate it."""
    if row.get("Source Type") != "cloud-posture":
        return None
    field = re.search(r"\.([A-Za-z_]\w*)$", str(row.get("JSON Path", "")))
    if not field:
        return None
    try:
        resource = json.loads(snippet)
    except (ValueError, TypeError):
        return None
    if isinstance(resource, dict) and field[1] in resource:
        return {field[1]: resource[field[1]]}
    return None


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


def _report_findings_from_dataframe(dataframe) -> list[dict[str, Any]]:
    """Adapt displayed CBOM fields for reporting, preserving unknown assessments."""
    return [{
        "algorithm_name": row["Algorithm"],
        "quantum_risk": row["Quantum Risk"].lower(),
        "classical_risk": row["Classical Risk"].lower(),
        "source_type": row["Source Type"], "source_path": row["Source Path"],
        "quantum_vulnerable": row["Quantum Vulnerable"].lower() == "true",
        "quantum_safe": row["Quantum Safe"].lower() == "true",
        "nist_standard": row["NIST References"], "reasoning": row["Description"],
    } for _, row in dataframe.iterrows()]


def _report_findings_from_cbom(cbom: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract an existing assessment without reinterpreting incomplete CBOM data."""
    return _report_findings_from_dataframe(load_findings_dataframe(cbom))


def _render_metrics(full_dataframe, summary=None) -> None:
    """Render decoupled Hygiene vs Posture metrics from the full CBOM."""
    total_assets = len(full_dataframe)
    if total_assets == 0:
        st.info("Run a scan to see results")
        return

    counts = (
        full_dataframe["Quantum Risk"]
        .value_counts()
        .reindex(RISK_ORDER, fill_value=0)
        .to_dict()
    )

    crit_count = int(counts.get("Critical", 0))
    med_count = int(counts.get("Medium", 0))
    safe_count = int(counts.get("Safe", 0))

    vuln_series = full_dataframe["Quantum Vulnerable"].astype(str).str.lower()
    vuln_count = int((vuln_series == "true").sum())

    if summary is not None:
        hygiene_score = summary["hygiene_score"]
    elif calculate_hygiene_score is not None:
        hygiene_score = calculate_hygiene_score(
            [{"classical_risk": row.get("Classical Risk", row["Quantum Risk"])} for _, row in full_dataframe.iterrows()]
        )
    else:
        hygiene_score = max(
            0,
            int(100 - (crit_count * CRIT_WEIGHT + med_count * MED_WEIGHT) / total_assets),
        )

    if calculate_posture_status is not None:
        raw_status = summary["posture_status"] if summary is not None else calculate_posture_status(
            [
                {
                    "quantum_risk": row["Quantum Risk"],
                    "classical_risk": row.get("Classical Risk", row["Quantum Risk"]),
                    "quantum_vulnerable": str(row["Quantum Vulnerable"]).lower() == "true",
                }
                for _, row in full_dataframe.iterrows()
            ]
        )
        posture_map = {
            "FAILING": "FAILING",
            "AT_RISK": "⚠️ AT RISK",
            "SECURE": "✅ SECURE",
            "NO_DATA": "ℹ️ NO DATA",
            "INCOMPLETE": "ℹ️ INCOMPLETE",
        }
        posture_status = posture_map.get(raw_status, "ℹ️ NO DATA")
    else:
        if crit_count > 0:
            posture_status = "FAILING"
        elif vuln_count > 0:
            posture_status = "⚠️ AT RISK"
        else:
            posture_status = "✅ SECURE"

    assessed = total_assets - int(counts.get("Unknown", 0))
    coverage = 100 * assessed / total_assets
    risk_score = (summary["risk_score"] if summary is not None else
                  round(100 * (crit_count + 0.3 * med_count) / assessed, 2) if assessed else 0.0)
    exposure_columns = st.columns(2)
    exposure_columns[0].metric("Quantum Risk Score", f"{risk_score:.2f}/100" if assessed else "N/A")
    exposure_columns[1].metric("Quantum Assessment Coverage", f"{coverage:.2f}%")
    st.caption(
        f"Higher score = greater quantum exposure. Assessed: {assessed}/{total_assets}. "
        "Unknown is excluded. Findings are observations, not unique systems."
    )

    columns = st.columns(5)
    if posture_status == "FAILING":
        columns[0].markdown(
            '<div style="font-size:14px;margin-bottom:8px">Posture Status</div>'
            '<div style="color:#ff4b4b;font-size:clamp(40px,4vw,56px);font-weight:800;line-height:1.15">FAILING</div>',
            unsafe_allow_html=True,
        )
    else:
        columns[0].metric("Posture Status", posture_status)
    columns[1].metric("Quantum Critical", crit_count)
    columns[2].metric("Quantum Medium", med_count)
    columns[3].metric("Quantum Safe", safe_count)
    columns[4].metric("Quantum Unknown", int(counts.get("Unknown", 0)))

    st.caption("Posture considers both risks. Safe applies only to evaluated criteria.")
    with st.expander("Classical assessment details", expanded=False):
        st.metric("Crypto Hygiene", f"{hygiene_score}/100")
        st.caption(
            "Classical assessment only. 100/100 does not imply quantum resilience. Unknown contributes no verified hygiene."
        )
    classical_critical = int((full_dataframe["Classical Risk"].astype(str).str.lower() == "critical").sum())
    if classical_critical:
        st.error(f"CLASSICAL RISK: {classical_critical} findings require remediation of classical weaknesses.")
    quantum_unknown = int((full_dataframe["Quantum Risk"].astype(str).str.lower() == "unknown").sum())
    classical_unknown = int((full_dataframe["Classical Risk"].astype(str).str.lower() == "unknown").sum())
    if quantum_unknown or classical_unknown:
        st.info(f"Unresolved: {quantum_unknown} quantum · {classical_unknown} classical.")

    if crit_count > 0:
        st.error(
            f"**MIGRATION REQUIRED:** {crit_count} Critical findings use cryptography vulnerable to quantum attacks.",
        )
    elif vuln_count > 0:
        st.warning(
            f"**QUANTUM EXPOSURE:** {vuln_count} assets use cryptography vulnerable to quantum attacks.",
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
        dataframe["Quantum Risk"]
        .value_counts()
        .reindex(RISK_ORDER, fill_value=0)
        .rename_axis("Quantum Risk")
        .reset_index(name="Findings")
    )

    chart_data = chart_data[chart_data["Findings"] > 0]

    if chart_data.empty:
        st.info("No findings match the selected filters.")
        return

    figure = px.pie(
        chart_data,
        names="Quantum Risk",
        values="Findings",
        hole=0.55,
        color="Quantum Risk",
        color_discrete_map=RISK_COLORS,
        category_orders={"Quantum Risk": RISK_ORDER},
    )

    figure.update_layout(
        template="plotly_dark",
        legend_title_text="Quantum Risk",
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
            # Scanners share the contract; protocol assessments retain context.
            if isinstance(finding, CryptoFinding):
                scanner_src = _get_finding_scanner_source(finding)
                if finding.source_type == "network-capture" and scanner_src == "real: scanner.pcap_scanner":
                    # Retain protocol context: negotiation, plaintext and SSH.
                    finding = finding.model_copy(deep=True)
                else:
                    finding = enrich_finding(finding)
                _set_finding_scanner_source(finding, scanner_src)
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


def _missing_language_scanner_warning(suffix: str) -> str | None:
    """The dispatcher can exist while a language implementation is unavailable."""
    language = {".py": ("Python", "python", "scan_python_file"), ".java": ("Java", "java", "scan_java_file")}.get(suffix)
    if language is None:
        return None
    label, module_name, method = language
    try:
        module = importlib.import_module(f"scanner.{module_name}_scanner")
        if callable(getattr(module, method, None)):
            return None
    except ImportError:
        pass
    return f"source-code ({label} scanner missing)"


def _scan_input_file(path: Path, label: str, warnings: list[str], outcomes: list[dict[str, Any]]) -> list[Any]:
    """Isolate each input failure and record the actual scanner outcome."""
    ext = path.suffix.lower()
    kind = ("cloud-posture" if ext == ".json" else "network-capture"
            if ext in (".pcap", ".pcapng") else "source-code")
    outcome = {"Input": len(outcomes) + 1, "File": label, "Source": kind,
               "Status": "Failed", "Findings": 0, "Scanner": "unknown", "Error": ""}
    outcomes.append(outcome)
    try:
        missing = _missing_language_scanner_warning(ext) if kind == "source-code" else None
        if missing and missing not in warnings:
            warnings.append(missing)
        scanner = (_get_cloud_scanner() if kind == "cloud-posture" else
                   _get_pcap_scanner() if kind == "network-capture" else _get_source_scanner_file())
        if scanner and not missing:
            module, method_name = scanner
            outcome["Scanner"] = f"real: {module.__name__}"
            logger.info("Using real scanner: %s (via %s) for %s", module.__name__, method_name, kind)
            results = getattr(module, method_name)(path)
        else:
            outcome["Scanner"] = "FALLBACK heuristic"
            logger.info("Using FALLBACK heuristic for %s: %s", kind, label)
            # Fallbacks return [] on unreadable inputs; distinguish that from a
            # successful limited scan with no matches.
            with path.open("rb") as input_file:
                input_file.read(1)
            if kind == "cloud-posture":
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                if not isinstance(data, dict):
                    raise ValueError("Expected a cloud JSON object")
            fallback = (_scan_cloud_file_fallback if kind == "cloud-posture" else
                        _scan_pcap_file_fallback if kind == "network-capture" else _scan_source_file_fallback)
            results = fallback(path)
        results = results if isinstance(results, list) else [results] if results else []
        _tag_findings_scanner_source(results, outcome["Scanner"])
        for finding in results:
            if isinstance(finding, CryptoFinding):
                finding.scan_input_id = outcome["Input"]
            elif isinstance(finding, dict):
                finding["scan_input_id"] = outcome["Input"]
            if hasattr(finding, "evidence") and finding.evidence:
                for evidence in finding.evidence:
                    recorded_path = Path(evidence.file_path)
                    if recorded_path == path or (len(recorded_path.parts) == 1 and recorded_path.name == path.name):
                        evidence.file_path = label
            elif isinstance(finding, dict):
                finding["source_path"] = label
        outcome["Findings"] = len(results)
        outcome["Status"] = "With findings" if results else "No detections"
        return results
    except Exception as exc:  # noqa: BLE001 - an invalid input must not hide other files
        outcome["Error"] = str(exc)
        warnings.append(f"Error scanning {label}: {exc}")
        return []


def _finish_scan(findings: list[Any], warnings: list[str], outcomes: list[dict[str, Any]]):
    if not findings:
        return None, warnings or ["No cryptographic findings detected in the scanned files."]
    cbom = _build_cbom_from_findings(findings)
    cbom.setdefault("metadata", {}).setdefault("properties", []).append({
        "name": "cryptotrace:scanOutcomes", "value": json.dumps(outcomes),
    })
    cbom["metadata"]["properties"].append({
        "name": "cryptotrace:scanCoverage", "value": json.dumps(summarize_scan_coverage(outcomes)),
    })
    return cbom, warnings


def scan_uploaded_files(
    uploaded_files: list[Any], *, outcomes: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Scan uploads independently, preserving duplicate names and per-input status."""
    if not uploaded_files:
        return None, ["No files selected for scanning."]
    outcomes = outcomes if outcomes is not None else []
    warnings: list[str] = []
    findings: list[Any] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        for index, upload in enumerate(uploaded_files):
            name = Path(upload.name).name
            if Path(name).suffix.lower() not in (".json", ".pcap", ".pcapng", ".py", ".java", ".go"):
                warnings.append(f"Skipped unsupported file: {name}")
                outcomes.append({"Input": len(outcomes) + 1, "File": name, "Source": "unsupported",
                                 "Status": "Skipped", "Findings": 0, "Scanner": "none", "Error": "Unsupported format"})
                continue
            folder = Path(temp_dir) / str(index)
            folder.mkdir()
            path = folder / name
            try:
                path.write_bytes(upload.getvalue())
            except Exception as exc:  # noqa: BLE001 - isolate upload read/write failures too
                warnings.append(f"Error reading {name}: {exc}")
                outcomes.append({"Input": len(outcomes) + 1, "File": name, "Source": "unknown",
                                 "Status": "Failed", "Findings": 0, "Scanner": "none", "Error": str(exc)})
                continue
            findings.extend(_scan_input_file(path, name, warnings, outcomes))
    return _finish_scan(findings, warnings, outcomes)


def scan_bundled_data(
    sample_dir: Path = DEFAULT_SAMPLE_DIR, *, outcomes: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Use the same per-file scanner workflow for bundled data and uploads."""
    outcomes = outcomes if outcomes is not None else []
    warnings: list[str] = []
    findings: list[Any] = []
    for folder, extensions in (("sample-repos", {".py", ".java", ".go"}),
                               ("cloud-posture", {".json"}), ("network-capture", {".pcap", ".pcapng"})):
        for path in sorted((sample_dir / folder).rglob("*")):
            if path.is_file() and path.suffix.lower() in extensions:
                findings.extend(_scan_input_file(path, path.relative_to(sample_dir).as_posix(), warnings, outcomes))
    return _finish_scan(findings, warnings, outcomes)


def _priority(row) -> int:
    """Presentation order only: critical, medium, unresolved, evaluated safe."""
    risks = {str(row.get(axis, "Unknown")).casefold() for axis in ("Quantum Risk", "Classical Risk")}
    return 0 if "critical" in risks else 1 if "medium" in risks else 2 if risks != {"safe"} else 3


def _prioritize_findings(dataframe):
    return (dataframe.assign(_priority=dataframe.apply(_priority, axis=1))
            .sort_values("_priority", kind="stable").drop(columns="_priority"))


def _priority_actions(dataframe):
    """Group identical recommendations at the same priority, retaining observation counts."""
    groups: dict[tuple[int, str], dict[str, Any]] = {}
    for _, row in dataframe.iterrows():
        priority = _priority(row)
        if priority == 3:
            continue
        action = str(row.get("Recommendation", "")).strip()
        if action.casefold() in ("", "unknown", "n/a", "none"):
            action = "Collect missing parameters/context and review the assessment."
        key = (priority, action)
        group = groups.setdefault(key, {"Priority": ("Critical", "Medium", "Unresolved")[priority],
                                       "Action": action, "Findings": 0, "Algorithms": set(), "Sources": set()})
        group["Findings"] += 1
        group["Algorithms"].add(str(row.get("Algorithm", "unknown")))
        group["Sources"].add(_finding_source_label(row))
    rows = []
    for key in sorted(groups):
        group = groups[key]
        rows.append({**group, "Algorithms": ", ".join(sorted(group["Algorithms"])),
                     "Sources": ", ".join(sorted(group["Sources"]))})
    return pd.DataFrame(rows, columns=["Priority", "Action", "Findings", "Algorithms", "Sources"])


def _scan_outcomes(cbom=None) -> list[dict[str, Any]]:
    metadata = cbom.get("metadata", {}) if isinstance(cbom, dict) else {}
    if not isinstance(metadata, dict):
        return []
    raw = _extract_property(metadata.get("properties", []), "cryptotrace:scanOutcomes")
    try:
        outcomes = (json.loads(raw) if raw != "unknown" else
                    st.session_state.get("scan_outcomes", []) if cbom is None else [])
    except (TypeError, ValueError):
        return []
    return outcomes if isinstance(outcomes, list) and all(isinstance(row, dict) for row in outcomes) else []


def _render_scan_coverage(cbom=None) -> None:
    coverage = summarize_scan_coverage(_scan_outcomes(cbom))
    st.metric("Input Scan Status", coverage["status"])
    if coverage["status"] == "Partial":
        st.warning(
            f"ANALYSIS PARTIAL: {coverage['failed_inputs']} failed, {coverage['skipped_inputs']} skipped, "
            f"{coverage['limited_inputs']} processed with limited discovery, {coverage['unrecorded_inputs']} unresolved. "
            "Posture and scores describe discovered findings only; they do not establish the safety of unassessed inputs."
        )
    elif coverage["status"] == "Complete":
        st.caption(f"All {coverage['total_inputs']} inputs were processed. No detections does not prove absence of cryptography.")
    else:
        st.caption("Input processing coverage is unavailable: this CBOM has no recorded file scan outcomes.")


def _render_scan_outcomes(cbom=None) -> None:
    outcomes = _scan_outcomes(cbom)
    if not outcomes:
        return
    with st.expander("File scan coverage", expanded=any(row.get("Status") == "Failed" for row in outcomes)):
        st.caption("Per input, before filters. No detections does not prove absence of cryptography. FALLBACK heuristic means limited discovery. Input numbers distinguish duplicate filenames.")
        st.dataframe(pd.DataFrame(outcomes), hide_index=True, use_container_width=True)


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
            if risk in set(dataframe["Quantum Risk"])
        ]

        selected_sources = st.multiselect(
            "Data source",
            options=source_options,
            default=source_options,
        )

        selected_risks = st.multiselect(
            "Quantum risk",
            options=risk_options,
            default=risk_options,
        )

        classical_options = [risk for risk in RISK_ORDER if risk in set(dataframe["Classical Risk"])]
        selected_classical = st.multiselect(
            "Classical risk", options=classical_options, default=classical_options,
        )
        observation_options = sorted(dataframe["Observation"].unique())
        selected_observations = st.multiselect(
            "Observation", options=observation_options, default=observation_options,
        )
        st.caption("All filters apply together. Advertised means offered capability; negotiated means selected or inferred selection, without proving session completion.")

        search_query = st.text_input(
            "Search algorithm or evidence",
            placeholder="RSA, SHA-1, source path, rule ID...",
        )

        if st.button("Clear active scan", use_container_width=True):
            st.session_state["cbom"] = None
            st.session_state["cbom_source"] = None
            st.session_state["scan_warnings"] = []
            st.session_state["scan_outcomes"] = []
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

    discovery_limits = []
    if "Scanner source" in dataframe.columns:
        fallback_mask = dataframe["Scanner source"] == "FALLBACK heuristic"
        if fallback_mask.any():
            used_types = sorted(
                str(t)
                for t in dataframe.loc[fallback_mask, "Source Type"].dropna().unique()
            )
            types_str = ", ".join(used_types) if used_types else "unknown inputs"
            discovery_limits.append(types_str)
    discovery_limits.extend(
        warning for warning in st.session_state.get("scan_warnings", [])
        if isinstance(warning, str) and "scanner missing" in warning
    )
    if discovery_limits:
        st.warning("⚠️ Fallback heuristic / incomplete discovery: " + "; ".join(discovery_limits)
                   + ". Policy expansion and network negotiation require the full scanners.")

    filtered_dataframe = dataframe[
        dataframe["Source Type"].isin(selected_sources)
        & dataframe["Quantum Risk"].isin(selected_risks)
        & dataframe["Classical Risk"].isin(selected_classical)
        & dataframe["Observation"].isin(selected_observations)
    ].copy()

    if search_query:
        query = search_query.casefold()
        search_mask = False

        searchable_columns = [
            "Algorithm",
            "Source Path",
            "Matched Snippet",
            "Rule ID",
            "NIST References",
            "Description",
            "Recommendation",
            "Library / API",
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

    filtered_dataframe = _prioritize_findings(filtered_dataframe)

    _render_scan_coverage(cbom)
    _render_metrics(dataframe, summary=build_report_summary(_report_findings_from_dataframe(dataframe)))

    chart_column, summary_column = st.columns([1, 1])

    with chart_column:
        st.subheader("Quantum risk distribution")
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
    st.caption("Order: Critical, Medium, Unresolved, Safe, considering both risk axes. Select a row for assessment, action and evidence. Unknown means the assessment is unresolved; Safe applies only to evaluated criteria.")
    with st.expander("Understanding Quantum Risk and Classical Risk", expanded=False):
        st.write("**Quantum:** exposure to the quantum attacks considered by the project.")
        st.write("**Classical:** strength of the known parameters/configuration against classical attacks.")
        st.write("**Critical:** a critical issue was identified. **Medium:** reduced margin or review required.")
        st.write("**Safe:** meets evaluated criteria. **Unknown:** insufficient information or unsupported assessment.")
        st.caption("Example: RSA-2048 can meet the classical key-size criterion while remaining quantum-critical due to Shor. Unknown does not mean safe.")

    if filtered_dataframe.empty:
        st.info("No findings match the selected filters.")
        _render_scan_outcomes(cbom)
        return

    display_columns = [
        "Algorithm",
        "Quantum Risk",
        "Classical Risk",
        "Recommendation",
        "Observation",
        "Description",
        "Scanner source",
        "Source Type",
        "Source Path",
        "Input ID",
        "Operation",
        "Line Number",
        "Library / API",
        "JSON Path",
        "Packet Number",
        "Matched Snippet",
        "Rule ID",
        "NIST References",
        "Quantum Vulnerable",
        "Quantum Safe",
        "BOM Reference",
    ]

    display_dataframe = filtered_dataframe[
        [
            column
            for column in display_columns
            if column in filtered_dataframe.columns
        ]
    ]

    # Key the selection to the filtered records so a filter change cannot inspect
    # a different row using a stale positional selection.
    selection_key = hashlib.sha256(filtered_dataframe.to_json().encode("utf-8")).hexdigest()[:16]
    event = st.dataframe(
        _style_dataframe(_compact_findings_dataframe(filtered_dataframe)),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=f"findings_overview_{selection_key}",
    )

    selected_rows = event.selection.rows
    if isinstance(selected_rows, (list, tuple)) and selected_rows:
        selected = selected_rows[0]
        if isinstance(selected, int) and 0 <= selected < len(filtered_dataframe):
            _render_finding_details(filtered_dataframe.iloc[selected], cbom)

    with st.expander("Full table — all finding fields", expanded=False):
        st.dataframe(_style_dataframe(display_dataframe), use_container_width=True, hide_index=True)

    st.caption("CSV includes all finding fields for the current filters, regardless of row selection. CBOM includes the complete scan inventory.")

    # Findings CSV download button
    st.download_button(
        label="Download Findings as CSV",
        data=display_dataframe.to_csv(index=False).encode("utf-8"),
        file_name="quantumtrace_findings.csv",
        mime="text/csv",
        use_container_width=True,
    )
    with st.expander("Priority actions - current filters", expanded=False):
        actions = _priority_actions(filtered_dataframe)
        st.caption("Identical recommendations grouped by priority. Counts are observations, including advertised capabilities; confirm context in the individual evidence before remediation.")
        if actions.empty:
            st.info("No critical, medium or unresolved findings in the current filters.")
        else:
            st.dataframe(actions, hide_index=True, use_container_width=True)
            st.download_button("Download priority actions as CSV", actions.to_csv(index=False).encode("utf-8"),
                               "quantumtrace_actions.csv", "text/csv")
    _render_scan_outcomes(cbom)



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

    if "scan_outcomes" not in st.session_state:
        st.session_state["scan_outcomes"] = []

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
                outcomes = []
                cbom_data, warnings = scan_uploaded_files(uploaded_files, outcomes=outcomes)
                st.session_state["scan_outcomes"] = outcomes
                st.session_state["cbom"] = cbom_data
                st.session_state["cbom_source"] = f"{len(uploaded_files)} uploaded file(s)"
                st.session_state["scan_warnings"] = warnings
            st.rerun()

    if scan_bundled_button:
        with st.spinner("Scanning bundled sample data..."):
            outcomes = []
            cbom_data, warnings = scan_bundled_data(outcomes=outcomes)
            st.session_state["scan_outcomes"] = outcomes
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
            st.session_state["scan_outcomes"] = []
        except Exception as exc:  # noqa: BLE001 - isolate CBOM upload parsing failure
            st.sidebar.error(f"Failed to load CBOM JSON: {exc}")

    if load_local_button:
        cbom_data, cbom_path = _load_default_cbom()
        if cbom_data is not None:
            st.session_state["cbom"] = cbom_data
            st.session_state["cbom_source"] = cbom_path
            st.session_state["scan_warnings"] = []
            st.session_state["scan_outcomes"] = []
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
        if st.session_state.get("scan_outcomes"):
            _render_scan_coverage()
        _render_scan_outcomes()

        return

    # Render dashboard from session state
    for warn in st.session_state.get("scan_warnings", []):
        st.warning(warn)

    render_dashboard(active_cbom, st.session_state.get("cbom_source"))


if __name__ == "__main__":
    main()

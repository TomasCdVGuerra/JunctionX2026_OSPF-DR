"""Streamlit dashboard for QuantumTrace CycloneDX 1.6 CBOM reports."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    import pandas as pd
    import streamlit as st
except ImportError:  # pragma: no cover
    pd = None
    st = None

try:
    import plotly.express as px
except ImportError:  # pragma: no cover
    px = None


DEFAULT_CBOM_PATH = Path("cbom.json")

RISK_ORDER = ["Critical", "Medium", "Safe", "Unknown"]
RISK_COLORS = {
    "Critical": "#dc2626",
    "Medium": "#f59e0b",
    "Safe": "#16a34a",
    "Unknown": "#6b7280",
}

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

    source_type = property_value("cryptotrace:sourceType")
    source_path = property_value("cryptotrace:sourcePath")
    operation = property_value("cryptotrace:operation")

    if source_path == "unknown":
        source_path = property_value("cryptotrace:filePath")

    if source_path == "unknown":
        source_path = evidence.get("Source Path", "unknown")

    if source_path == "unknown":
        source_path = _normalise(component.get("source"))

    row = {
        "Algorithm": _normalise(component.get("name")),
        "Risk Rating": risk_rating,
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
        "NIST Standard": evidence.get(
            "NIST Standard",
            "unknown",
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
        """Load and cache CBOM data.

        ``file_mtime`` is deliberately part of the cache key so a newly
        generated local CBOM invalidates the previous cached value.
        """
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
    cbom: dict[str, Any],
):
    """Convert CBOM cryptographic components into a Pandas DataFrame."""
    if pd is None:
        raise RuntimeError("Pandas is required to build the findings table.")

    components = cbom.get("components", [])
    if not isinstance(components, list):
        components = []

    rows = [
        _component_to_row(component)
        for component in components
        if isinstance(component, dict)
    ]

    columns = [
        "Algorithm",
        "Risk Rating",
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
    """Style risk cells across supported Pandas versions."""
    styler = dataframe.style
    style_function = getattr(styler, "map", None)

    if style_function is None:
        style_function = getattr(styler, "applymap", None)

    if style_function is None:
        return dataframe

    return style_function(_risk_css, subset=["Risk Rating"])


def _safe_text_columns(dataframe):
    """Ensure searchable columns contain non-null strings."""
    for column in ("Algorithm", "Source Path", "Matched Snippet", "Rule ID"):
        if column not in dataframe.columns:
            dataframe[column] = "unknown"

        dataframe[column] = dataframe[column].fillna("unknown").astype(str)

    return dataframe


def render_cli_fallback_notice() -> None:
    """Display CLI instructions when the dashboard cannot run normally."""
    if st is None:
        print(
            "Streamlit is not installed. Run the scanner from a terminal "
            "with: python main.py --all"
        )
        return

    st.info(
        "For headless environments, use the terminal report instead: "
        "`python main.py --all --output cbom.json`."
    )


def _render_metrics(dataframe) -> None:
    """Render risk counters and normalized exposure metrics."""
    total = len(dataframe)

    counts = (
        dataframe["Risk Rating"]
        .value_counts()
        .reindex(RISK_ORDER, fill_value=0)
        .to_dict()
    )

    critical_count = int(counts["Critical"])
    medium_count = int(counts["Medium"])
    safe_count = int(counts["Safe"])
    unknown_count = int(counts["Unknown"])

    raw_score = (
        critical_count * CRITICAL_WEIGHT
        + medium_count * MEDIUM_WEIGHT
    )

    vulnerable_percentage = (
        critical_count / total * 100
        if total
        else 0
    )

    columns = st.columns(5)

    columns[0].metric(
        "Quantum Risk Score",
        raw_score,
        delta=f"{vulnerable_percentage:.1f}% critical",
        delta_color="inverse",
    )
    columns[1].metric("Critical", critical_count)
    columns[2].metric("Medium", medium_count)
    columns[3].metric("Safe", safe_count)
    columns[4].metric("Unknown", unknown_count)


def _render_risk_chart(dataframe) -> None:
    """Render a stable-order risk distribution chart."""
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
        legend_title_text="Risk Rating",
        margin=dict(l=10, r=10, t=20, b=10),
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


def render_dashboard(
    cbom: dict[str, Any],
    cbom_path: str | Path | None = None,
) -> None:
    """Render the interactive CBOM dashboard."""
    if st is None:
        render_cli_fallback_notice()
        return

    with st.sidebar:
        st.header("Filters")

        uploaded_file = st.file_uploader(
            "Upload another CBOM",
            type=["json"],
        )

        if uploaded_file is not None:
            try:
                cbom = load_cbom(
                    file_bytes=uploaded_file.getvalue(),
                    filepath="",
                    file_mtime=None,
                )
                cbom_path = uploaded_file.name
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                st.error(f"Unable to load CBOM JSON: {exc}")
                return

        dataframe = _safe_text_columns(
            load_findings_dataframe(cbom)
        )

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

        if st.button("Reload CBOM", use_container_width=True):
            st.cache_data.clear()
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

    _render_metrics(filtered_dataframe)

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
        "Risk Rating",
        "Source Type",
        "Source Path",
        "Operation",
        "Line Number",
        "Matched Snippet",
        "Rule ID",
        "NIST Standard",
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

    cbom, cbom_path = _load_default_cbom()

    if cbom is None:
        st.title("QuantumTrace Cryptographic Risk Dashboard")
        st.warning(
            "No `cbom.json` file was found. Run the scanner first:"
        )
        st.code("python main.py --all --output cbom.json")
        render_cli_fallback_notice()
        return

    render_dashboard(cbom, cbom_path)


if __name__ == "__main__":
    main()
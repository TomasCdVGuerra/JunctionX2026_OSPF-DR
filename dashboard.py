# Purpose:
# Streamlit web interface presenting an interactive quantum risk dashboard, findings evidence explorer, and CBOM exporter.
#
# Responsibilities:
# - Render an executive Quantum Risk Score card with clear color indicators (Critical = Red, Medium = Orange, Safe = Green).
# - Display an interactive data table of all detected findings with searchable evidence columns (file path, line number, code snippet, rule ID, NIST standard).
# - Provide a one-click download button for the generated CycloneDX 1.6 CBOM JSON document.
# - Provide filters for data source (Source Code, Cloud Posture, PCAP) and risk tier.
# - Gracefully document fallback instructions to the Rich CLI terminal summary if Streamlit is not installed or run in headless mode.
#
# Planned interface:
# - render_dashboard(findings: list[CryptoFinding], cbom_path: Path) -> None: primary Streamlit application rendering metrics, charts, and tables.
# - load_findings_dataframe(findings: list[CryptoFinding]) -> pd.DataFrame: formats findings and evidence into a tabular presentation.
# - render_cli_fallback_notice() -> None: displays instructions for viewing terminal Rich output when browser UI is unavailable.
#
# Rules and edge cases:
# - Must handle large finding lists without sluggish UI performance by using efficient data table pagination.
# - If CBOM JSON has not yet been generated on disk, generate it dynamically in memory for the download button.
# - Display "unknown" clearly in table cells when attributes could not be inferred statically.
# - When run without Streamlit (e.g. standard terminal execution), point users directly to the Rich CLI report.
#
# Scoring link:
# - Usability and demo (15%): Delivers an engaging, interactive visual presentation for judges during hackathon demos.
# - Standardisation and traceability (20%): Exposes the downloadable CycloneDX 1.6 CBOM and complete evidence chain directly in the UI.

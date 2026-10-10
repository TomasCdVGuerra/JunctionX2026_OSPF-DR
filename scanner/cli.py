# Purpose:
# Command-line interface handling user arguments, multi-source pipeline execution, and terminal report rendering.
#
# Responsibilities:
# - Parse CLI options for target paths (--source, --cloud, --pcap, --all, --output, --verbose).
# - Coordinate execution sequence: source scanning, cloud posture parsing, PCAP analysis, and report generation.
# - Output a formatted summary table displaying detected algorithms, risk levels, security bit strengths, and primary locations.
# - Trigger CycloneDX 1.6 CBOM serialization and persist output to the specified JSON path.
# - Provide clear exit codes indicating execution success or critical operational errors.
#
# Planned interface:
# - build_cli_parser() -> argparse.ArgumentParser: constructs CLI flags and descriptions.
# - execute_pipeline(args: argparse.Namespace) -> int: orchestrates scanner modules and returns process exit code.
# - render_terminal_summary(findings: list[CryptoFinding], report_summary: dict[str, Any]) -> None: displays Rich or ASCII summary table.
#
# Rules and edge cases:
# - When --all is passed, automatically default paths to support-materials/ directories if present.
# - Handle missing input directories gracefully with informative warnings rather than unhandled tracebacks.
# - Ensure exit code 0 on successful scan even when critical quantum vulnerabilities are found (findings are reported, not treated as tool crashes).
#
# Scoring link:
# - Usability and demo (15%): Delivers intuitive CLI flags, polished terminal visuals, and friction-free user workflows.
# - Coverage (25%): Unifies all three input vectors (source, cloud, network) into a single command invocation.

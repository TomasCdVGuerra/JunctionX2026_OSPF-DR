# Purpose:
# Integration test suite validating end-to-end command-line interface execution, argument handling, and pipeline output.
#
# Responsibilities:
# - Test CLI argument combinations (--source, --cloud, --pcap, --all, --output, --verbose).
# - Verify that running the full pipeline generates an output CBOM JSON file on disk.
# - Test fallback default path resolution when running with the --all flag.
# - Assert that the process exits with standard code 0 upon successful scan execution.
#
# Planned interface:
# - test_cli_argument_parsing(): tests flag handling and default assignments.
# - test_end_to_end_pipeline_execution(tmp_path: Path): executes scan against test fixtures and checks generated CBOM file existence.
# - test_cli_help_and_version(): verifies --help and version output.
#
# Rules and edge cases:
# - Ensure integration tests do not leave temporary output files in the repository root (use pytest tmp_path fixture).
# - Validate that non-existent target paths produce clean error messages rather than raw unhandled exceptions.
#
# Scoring link:
# - Usability and demo (15%): Validates dependable CLI UX and automated execution.
# - Coverage (25%): Verifies end-to-end integration across all scanner subsystems.

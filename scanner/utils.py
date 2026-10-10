# Purpose:
# Shared utility functions providing logging configuration, safe JSON persistence, and formatted table generation.
#
# Responsibilities:
# - Configure unified application logging with support for verbose debug modes.
# - Provide recursive filesystem traversal helpers filtered by target extensions.
# - Render clean tabular views using the Rich library when available, with resilient plain-ASCII fallback formatting.
# - Provide atomic, UTF-8 encoded JSON persistence functions with directory auto-creation.
#
# Planned interface:
# - setup_logging(verbose: bool) -> None: initializes root logger format and thresholds.
# - find_files_by_extensions(root_path: Path, extensions: list[str]) -> list[Path]: collects matching file paths recursively.
# - format_table(headers: list[str], rows: list[list[str]]) -> str: renders colorized or plain ASCII table.
# - save_json(data: Any, target_file: Path) -> None: serializes data structure to formatted JSON on disk.
#
# Rules and edge cases:
# - Must handle environments where third-party packages (e.g. rich) are not yet installed without failing.
# - Ensure file read operations use error replacement strategies to avoid decoding crashes on non-UTF-8 source files.
# - Avoid writing temporary files outside designated project paths.
#
# Scoring link:
# - Usability and demo (15%): Provides attractive, readable terminal summaries and robust logging for live debugging.

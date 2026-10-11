"""CLI entrypoint temporarily disabled.

The supported application interface is the Streamlit dashboard.
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "The QuantumTrace CLI is temporarily disabled. "
        "Run the Streamlit dashboard instead.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

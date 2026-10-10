"""Primary CLI application entrypoint invoking the QuantumTrace scanner pipeline."""

from __future__ import annotations

import sys

from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())

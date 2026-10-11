#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
mode="${1:---ui}"
case "$mode" in
  --setup|--test|--ui) ;;
  *) echo "Usage: bash run.sh [--setup|--test|--ui]" >&2; exit 2 ;;
esac
if [[ ! -f .venv/bin/python && ! -f .venv/Scripts/python.exe ]]; then
  python3.13 -m venv .venv
fi
if [[ -f .venv/Scripts/python.exe ]]; then
  project_python=.venv/Scripts/python.exe
else
  project_python=.venv/bin/python
fi
"$project_python" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 13) else 1)' || {
  echo '.venv must use Python 3.13. Rename the old environment and create it again.' >&2
  exit 1
}
"$project_python" -m pip install -r requirements.txt
"$project_python" scripts/check_environment.py
case "$mode" in
  --test) "$project_python" -m pytest -q ;;
  --ui) "$project_python" -m streamlit run dashboard.py ;;
esac

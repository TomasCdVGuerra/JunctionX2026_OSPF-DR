#!/usr/bin/env bash
# Purpose:
# One-command automated setup, environment validation, scanner execution, and test verification script.
#
# Responsibilities:
# - Check for Python 3.12 installation and create a local virtual environment (.venv) if one does not exist.
# - Activate the virtual environment and install project dependencies from requirements.txt.
# - Execute the full test suite with pytest to ensure offline schema validation and ground-truth assertions pass.
# - Run the main scanner pipeline (python main.py --all --output cbom.json) to generate the CycloneDX 1.6 CBOM.
# - Optionally launch the interactive Streamlit dashboard (streamlit run dashboard.py) if --dashboard flag is passed.
#
# Planned interface:
# - ./run.sh            : runs environment setup, unit tests, and full CLI scan, producing cbom.json.
# - ./run.sh --test     : runs only the pytest test suite.
# - ./run.sh --ui       : runs the scan and launches the Streamlit visual dashboard.
#
# Rules and edge cases:
# - Abort immediately with clear error messages if Python 3.12 is missing or virtual environment creation fails.
# - Ensure tests pass before generating output to prevent invalid CBOM artifacts from being produced.
# - Handle headless environments cleanly when dashboard execution is requested without a browser.
#
# Scoring link:
# - Usability and demo (15%): Provides a seamless, friction-free one-command execution flow for hackathon judges and evaluators.

# QuantumTrace

> **Post-Quantum Cryptographic Discovery Scanner and CycloneDX 1.6 CBOM Analytics Engine**

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-success.svg)](https://cyclonedx.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

QuantumTrace is an automated post-quantum cryptographic discovery and posture management platform designed to identify Shor- and Grover-vulnerable algorithms across multi-language source code, AWS cloud posture configurations, and network traffic captures.

---

## ⚡ Quickstart

QuantumTrace includes cross-platform bootstrap scripts ([run.sh](run.sh) for macOS/Linux and [run.ps1](run.ps1) for Windows) that automate the entire setup and launch process in a single command.

### Automated Launchers (`run.sh` & `run.ps1`)

Both scripts automatically perform the following steps:
1. **Directory Alignment**: Resolves to the repository root directory regardless of invocation path.
2. **Virtual Environment Bootstrap**: Automatically creates a `.venv` using **Python 3.13** (`python3.13` on macOS/Linux, `py -3.13` on Windows) if not present.
3. **Strict Python 3.13 Check**: Verifies that the `.venv` interpreter strictly matches Python 3.13 (`sys.version_info[:2] == (3, 13)`).
4. **Dependency Sync**: Automatically installs and syncs dependencies from `requirements.txt`.
5. **Pre-flight Health Check**: Runs `scripts/check_environment.py` to validate system prerequisites and tool availability.
6. **Execution by Mode**: Launches the Streamlit dashboard, executes the test suite, or finishes after setup.

#### Linux / macOS ([run.sh](run.sh))
```bash
# Launch the Streamlit dashboard (default)
bash run.sh
# or explicitly:
bash run.sh --ui

# Run the test suite via pytest
bash run.sh --test

# Setup environment & dependencies only (useful for CI/CD or initial setup)
bash run.sh --setup
```

#### Windows PowerShell ([run.ps1](run.ps1))
```powershell
# Launch the Streamlit dashboard (default)
.\run.ps1
# or explicitly:
.\run.ps1 -Mode ui

# Run the test suite via pytest
.\run.ps1 -Mode test

# Setup environment & dependencies only
.\run.ps1 -Mode setup
```

---

### Manual Setup (Alternative)

If you prefer to manage the virtual environment manually:

```bash
# 1. Create and activate Python 3.13 virtual environment
python3.13 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify environment
python scripts/check_environment.py

# 4. Launch the dashboard
streamlit run dashboard.py

# 5. Run the test suite
python -m pytest -q
```

---

### Prerequisites & TShark Configuration

* **TShark / Wireshark**: Required only for live PCAP packet captures (it is an external system tool, not a Python package). Code and cloud posture scans do not require TShark.
* The scanner automatically detects `tshark` via `TSHARK_PATH`, system `PATH`, or standard Wireshark installation directories.
* On Windows, if TShark is installed in a custom location, set the environment variable before starting:
  ```powershell
  $env:TSHARK_PATH = 'C:\Program Files\Wireshark\tshark.exe'
  .\run.ps1
  ```
* Network findings preserve the protocol analyzers' packet-level context and assessments; missing TShark reports an explicit diagnostic warning in the UI rather than silently skipping network data.

---

## 📖 Documentation

For detailed architecture diagrams, cryptographic threat models, CBOM schema mappings, and hackathon presentation notes, see:

* **[Comprehensive Documentation](docs/README.md)**: Full architecture breakdown, scoring metrics, and cryptographic risk classifications.
* **[Developer Setup & Architecture](docs/DEV_SETUP.md)**: Development guidelines, environment configuration, and test suites.
* **[Demo and integration checklist](docs/DEMO.md)**: Inputs, expected inventory counts, filters and export checks.

---

## 🛡️ Core Capabilities

* **Multi-Vector Discovery**: Go, Python AST and Java token-based source scanners, AWS cloud posture exports (KMS, ALB, ACM), and packet captures share the finding contract. Source analysis recognizes supported APIs; an empty result does not prove absence of cryptography.
* **CycloneDX 1.6 CBOM Export**: Schema-validated exports with native `cryptoProperties` for known metadata, deterministic component references, full evidence chains, classical risk tracking (`cryptotrace:classicalRisk`), and risk ratings. Resolved source library/API namespaces appear in the table and CSV; implementation providers and versions are not assumed.
* **Centralized Risk & Reporting Engine**: Powers the Streamlit dashboard via `scanner/risk.py` and `scanner/report.py`.
  * **Quantum Risk Score**: `100 × (Critical + 0.3 × Medium) / assessed findings`, shown beside quantum assessment coverage. Unknown findings are excluded from the score; no assessed findings displays N/A. Higher scores mean greater exposure.
  * **Crypto Hygiene**: A classical assessment score from 0 to 100, penalizing unresolved findings for incomplete coverage. It is not a certification or proof of compromise.
  * **Posture Status**: `FAILING` for critical risk on either axis, `AT_RISK` for medium risk, `INCOMPLETE` when assessment remains unknown, `SECURE` when all findings are safe under the evaluated criteria, or `NO_DATA` for an empty inventory. Protocol findings retain the network analyzers' context.
  * **Dual-Axis Risk Model**: Explicitly tracks **Quantum Risk** (exposure to quantum attacks) and **Classical Risk** (known classical parameters/configuration). RSA-2048 signing keys are quantum-critical while meeting the evaluated classical key-size criterion. Safe does not certify the implementation.
  * **Input processing coverage**: Complete, Partial or Unknown is displayed independently of finding posture. Failures and limited discovery remain visible even when discovered findings are safe. Input IDs link repeated filenames to findings, CSV and CBOM.

Dependencies are pinned in `requirements.txt` from a validated clean Python 3.13
environment. GitHub Actions tests Windows and Linux; Linux also requires a real
TShark check against reviewed packets in the supplied capture. See
[risk policy](docs/RISK_POLICY.md) for shared criteria and protocol exceptions.
  * **Independent Executive Metrics**: Executive metrics are calculated from the complete active scan inventory, ensuring high-level posture remains accurate while search and filter controls narrow detailed tabular views.

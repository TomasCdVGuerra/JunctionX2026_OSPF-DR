# QuantumTrace

> **Post-Quantum Cryptographic Discovery Scanner and CycloneDX 1.6 CBOM Analytics Engine**

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-success.svg)](https://cyclonedx.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

QuantumTrace is an automated post-quantum cryptographic discovery and posture management platform designed to identify Shor- and Grover-vulnerable algorithms across multi-language source code, AWS cloud posture configurations, and network traffic captures.

---

## ⚡ Quickstart

### 1. Installation

Windows PowerShell: `./run.ps1` prepares Python 3.13's `.venv`, installs
`requirements.txt`, checks TShark availability and starts the dashboard.
Use `./run.ps1 -Mode setup` for setup only or `./run.ps1 -Mode test` for the full suite.
Linux/macOS: `bash run.sh --ui` (`--setup` / `--test` are also supported).
TShark/Wireshark is installed separately and is required only for real PCAP scans.

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Analytics Dashboard

> **Note**: The Streamlit dashboard is the primary supported interface for this release. The CLI (`main.py`) is temporarily disabled while cloud and network scan pipelines are being unified.

```bash
streamlit run dashboard.py
```

PCAP uploads use the real network scanner through `scanner/pcap_scanner.py`.
Install Wireshark with TShark separately; it is not a Python dependency.
The scanner searches `TSHARK_PATH`, then `PATH`, then standard Wireshark folders.
On Windows, if detection fails, set this before starting Streamlit:

```powershell
$env:TSHARK_PATH = 'C:\Program Files\Wireshark\tshark.exe'
python -m streamlit run dashboard.py
```

Network findings retain the protocol analyzers' assessments and packet evidence;
the dashboard does not overwrite them with a primitive-only reassessment.
Advertised capabilities, negotiated selections and observed plaintext remain
separate findings. A TShark failure is reported instead of using a silent fallback.

### 3. Run the Test Suite

```bash
python -m pytest -q
```

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

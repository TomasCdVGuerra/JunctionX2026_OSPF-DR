# QuantumTrace

> **Post-Quantum Cryptographic Discovery Scanner and CycloneDX 1.6 CBOM Analytics Engine**

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-success.svg)](https://cyclonedx.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

QuantumTrace is an automated post-quantum cryptographic discovery and posture management platform designed to identify Shor- and Grover-vulnerable algorithms across multi-language source code, AWS cloud posture configurations, and network traffic captures.

---

## ⚡ Quickstart

Install **Python 3.13** first. Install **Wireshark/TShark** separately to analyze
real PCAP files; source and cloud scans work without it. Internet access is
needed for the first dependency installation.

From the repository folder, run one command:

```powershell
# Windows
py -3.13 run.py
```

```bash
# Linux / macOS
python3.13 run.py
```

The script creates/reuses `.venv`, installs the pinned `requirements.txt`,
checks dependencies and TShark, then launches the dashboard at
**http://localhost:8501**. No environment activation is needed. Subsequent runs
skip downloads when the pinned dependencies already match. Stop with Ctrl+C.

An incompatible existing `.venv` is preserved: rename it and rerun.
If port 8501 is occupied, add `--port 8502`.

### Other modes

> **Note**: The Streamlit dashboard is the primary supported interface for this release. The CLI (`main.py`) is temporarily disabled while cloud and network scan pipelines are being unified.

```powershell
# Prepare only; require full PCAP support for the demo
py -3.13 run.py --setup --require-tshark
# Prepare and run all tests
py -3.13 run.py --test
```

On Linux/macOS use `python3.13` with the same arguments. `run.py` is the
single setup and launch entrypoint on all three operating systems.

Dependencies, including pytest, are installed in the project's `.venv`.
The script does not activate your terminal: use `run.py --test` to run tests
in that environment without reinstalling requirements. To run `python -m pytest`
directly, activate `.venv` in your terminal first (see [developer setup](docs/DEV_SETUP.md)).

PCAP uploads use the real network scanner through `scanner/pcap_scanner.py`.
Install Wireshark with TShark separately; it is not a Python dependency.
The scanner searches `TSHARK_PATH`, then `PATH`, then standard Wireshark folders.
On Windows, if detection fails, set this before starting Streamlit:

```powershell
$env:TSHARK_PATH = 'C:\Program Files\Wireshark\tshark.exe'
py -3.13 run.py --require-tshark
```

Network findings retain the protocol analyzers' assessments and packet evidence;
the dashboard does not overwrite them with a primitive-only reassessment.
Advertised capabilities, negotiated selections and observed plaintext remain
separate findings. A TShark failure is reported instead of using a silent fallback.

For the submission rehearsal, use `--test --require-tshark`, then run the
dashboard and follow [the demo checklist](docs/DEMO.md).

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
environment. GitHub Actions is configured for Windows, Linux and macOS; Linux/macOS require a real
TShark check against reviewed packets in the supplied capture. See
[risk policy](docs/RISK_POLICY.md) for shared criteria and protocol exceptions.
  * **Independent Executive Metrics**: Executive metrics are calculated from the complete active scan inventory, ensuring high-level posture remains accurate while search and filter controls narrow detailed tabular views.

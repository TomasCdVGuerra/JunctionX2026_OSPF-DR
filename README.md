# QuantumTrace

> **Post-Quantum Cryptographic Discovery Scanner and CycloneDX 1.6 CBOM Analytics Engine**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-success.svg)](https://cyclonedx.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

QuantumTrace is an automated post-quantum cryptographic discovery and posture management platform designed to identify Shor- and Grover-vulnerable algorithms across multi-language source code, AWS cloud posture configurations, and network traffic captures.

---

## ⚡ Quickstart

### 1. Installation

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

### 3. Run the Test Suite

```bash
python -m pytest tests -v
```

---

## 📖 Documentation

For detailed architecture diagrams, cryptographic threat models, CBOM schema mappings, and hackathon presentation notes, see:

* **[Comprehensive Documentation](docs/README.md)**: Full architecture breakdown, scoring metrics, and cryptographic risk classifications.
* **[Developer Setup & Architecture](docs/DEV_SETUP.md)**: Development guidelines, environment configuration, and test suites.

---

## 🛡️ Core Capabilities

* **Multi-Vector Discovery**: Static analysis of Go, Python, Java source code, AWS cloud posture exports (KMS, ALB, ACM), and packet captures.
* **CycloneDX 1.6 CBOM Export**: Generates compliant Cryptography Bill of Materials with deterministic component references, full evidence chains, classical risk tracking (`cryptotrace:classicalRisk`), and risk ratings.
* **Centralized Risk & Reporting Engine**: Powers the Streamlit dashboard via `scanner/risk.py` and `scanner/report.py`.
  * **Quantum Risk Score**: An exposure score from 0 to 100 representing quantum vulnerability exposure ($1.0 \times \text{Critical} + 0.3 \times \text{Medium}$).
  * **Crypto Hygiene**: A health score from 0 to 100 measuring the proportion of safe cryptographic assets.
  * **Posture Status**: Categorical compliance state: `FAILING` (critical quantum vulnerabilities present), `AT_RISK` (medium quantum exposure), `SECURE` (all cryptography quantum-resistant), or `NO_DATA` (empty inventory).
  * **Dual-Axis Risk Model**: Explicitly tracks **Quantum Risk** (future exposure to Shor/Grover attacks) and **Classical Risk** (current pre-quantum cryptographic strength). For example, RSA-2048 is `Quantum Risk: Critical` (broken by Shor's algorithm) while `Classical Risk: Safe` (not classically broken).
  * **Independent Executive Metrics**: Executive metrics are calculated from the complete active scan inventory, ensuring high-level posture remains accurate while search and filter controls narrow detailed tabular views.

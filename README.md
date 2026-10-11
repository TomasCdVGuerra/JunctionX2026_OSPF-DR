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
* **CycloneDX 1.6 CBOM Export**: Generates compliant Cryptography Bill of Materials with deterministic component references, full evidence chains, and risk ratings.
* **Quantum Risk Engine**: Rigorously categorizes cryptographic algorithms into `Critical`, `Medium`, `Safe`, and `Unknown` based on Shor's and Grover's quantum threat specifications.

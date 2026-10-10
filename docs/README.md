# QuantumTrace — team OSPF-DR

**JunctionX Lisbon 2026 — Inspiring Solutions Challenge**

QuantumTrace is an automated post-quantum cryptographic discovery scanner and compliance dashboard that inventories cryptographic assets across source code, AWS cloud posture exports, and network packet captures. It maps detected algorithms against NIST Post-Quantum Cryptography standards (FIPS 203, 204, 205), evaluates quantum and classical risk exposure, and exports an official CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).

---

## Quick Start

### 1. Environment Setup
QuantumTrace was verified on **Python 3.13** (macOS, Linux, Windows).

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install project dependencies
pip install -r requirements.txt
```

### 2. Launch the Interactive Dashboard
```bash
streamlit run dashboard.py
```
* Once the dashboard opens in your browser (`http://localhost:8501`), click **"Scan bundled sample data"** in the sidebar for an instant demonstration of the complete inventory and risk scoring.
* Alternatively, upload your own `.py`, `.java`, `.go`, `.json`, or `.pcap` files and click **"Scan uploaded files"**.

### 3. Run the Test Suite
```bash
python -m pytest tests -v
```
All unit tests, contract tests, and CycloneDX 1.6 offline schema validations run without external network access.

*(Note: The command-line script `main.py` and `run.sh` are currently placeholder scaffolding in this branch; the primary functional interface is the interactive Streamlit dashboard).*

---

## What It Scans

| Input Category | Supported Types & Formats | Status | Implementation Details |
| :--- | :--- | :---: | :--- |
| **Source Code** | Python (`.py`), Java (`.java`), Go (`.go`) | **Working** | Scans JCA/JCE APIs, `hashlib`/`cryptography`, and Go `crypto/*` standard packages. Resolves same-file constants to infer key sizes. |
| **AWS Cloud Posture** | KMS (`kms_key_inventory.json`), ALB (`load_balancer_listeners.json`), ACM (`acm_certificates.json`) | **Working** | Ingests AWS configuration dumps. Identifies KMS `KeySpec`, ACM certificate keys, and expands ELB `SslPolicy` configurations (flags unencrypted HTTP port 80). |
| **Network Traffic** | PCAP / PCAPNG captures (`network.pcap`) | **Partial** | Built-in heuristic inspector parses TLS Client/ServerHello handshakes and flags cleartext HTTP. A dedicated TShark parser exists on the separate `network_scanner` branch (**Not merged**). |

---

## Risk Tiers

Findings are evaluated against post-quantum threat models (Shor's and Grover's algorithms) and classical security guidelines:

* **Critical**: Schemes vulnerable to polynomial-time break by **Shor's algorithm**, including all asymmetric key exchange and public-key algorithms regardless of key size:
  * RSA (1024, 2048, 3072, 4096)
  * Elliptic Curve Cryptography: ECDSA, ECC curves (P-256, P-384), Ed25519, ECDH
  * Diffie-Hellman (DH), DSA
* **Medium**: Symmetric primitives whose effective security is halved by **Grover's algorithm** below the 128-bit quantum security threshold:
  * AES-128 (halved to 64 bits of quantum security)
  * Triple DES (3DES)
* **Safe**: Quantum-resistant symmetric primitives and NIST post-quantum standards:
  * AES-256, AES-256-GCM
  * SHA-2 family (SHA-256, SHA-384, SHA-512)
  * HMAC-SHA256, PBKDF2 with SHA-256
  * NIST PQC Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)

### Handling of Classically Broken Algorithms
In this codebase, classically broken primitives (**MD5**, **SHA-1**, **RSA-1024**, and **AES in ECB mode**) are assigned directly to the **Critical** tier. Their evidence reasoning explicitly cites classical vulnerabilities (e.g. practical collision attacks or ECB pattern leakage). There is no separate boolean `deprecated` flag; classical failure is enforced as an immediate Critical classification.

*(Note: The bundled sample dataset contains zero Medium findings because all symmetric ciphers in the sample repos are 256-bit AES, while legacy hashes and RSA are classified as Critical).*

---

## Scoring Model: Hygiene vs Posture

QuantumTrace separates volume-based health (**Crypto Hygiene**) from fatal single points of failure (**Posture Status**):

### 1. Crypto Hygiene Score (`0–100`)
$$\text{Crypto Hygiene} = \max\left(0, \operatorname{int}\left(100 - \frac{\text{Critical} \times 100 + \text{Medium} \times 30}{\text{Total Assets}}\right)\right)$$

* Measures the proportion of healthy cryptographic assets across the entire inventory.
* Penalizes **100 points per Critical** and **30 points per Medium** finding, averaged across all inventoried assets.
* Safe and unrecognised assets carry **0 penalty**, contributing positively to the overall denominator.

### 2. Posture Status
* **🚨 FAILING**: Triggered if any Critical finding exists (`crit_count > 0`). Displays an immediate migration alert banner.
* **⚠️ AT RISK**: Triggered if quantum-vulnerable assets exist without Critical findings (`vuln_count > 0`).
* **✅ SECURE**: All inventoried cryptography is quantum-resistant.

---

## Example Scan Results (Bundled Dataset)

*Scan executed against challenge reference material in `support-materials/` using bundled sample fixtures and baseline heuristics:*

* **Total Cryptographic Components Discovered:** **62** *(reference bundled test run)*
* **Counts by Source Type:**
  * Source Code (`.py`, `.java`, `.go`): **38**
  * AWS Cloud Posture (KMS, ALB, ACM JSON): **22**
  * Network Traffic (`network.pcap`): **2**
* **Counts by Risk Tier:**
  * **Critical:** 49
  * **Medium:** 0
  * **Safe:** 13
* **Crypto Hygiene Score:** **20 / 100**
* **Posture Status:** **🚨 FAILING**
  * Alert: *"MIGRATION REQUIRED: 49 Critical findings use cryptography vulnerable to quantum attacks."*

> *Note: Production pipeline runs dynamically invoke language-specific AST/static analysis engines (such as `scanner.go_scanner`) which produce precise, context-aware findings with zero false-positive comment leakage.*

---

## Output and Traceability

* **Traceable Evidence**: Every finding records granular audit metadata, including source file path, line number (or JSON path / packet offset), matched code snippet, rule ID, NIST standard mapping, and single-sentence risk reasoning.
* **CycloneDX 1.6 CBOM**: Serializes findings into standard CycloneDX 1.6 JSON (`cbom.json`). Component references (`bom-ref`) are deterministically hashed from `source_type:source_path:algorithm:operation`.
* **Export Options**: One-click download of the UTF-8 `cbom.json` and CSV findings table directly from the dashboard UI.
* **Schema Validation**: CBOM output is verified offline against the official CycloneDX 1.6 JSON Schema (`tests/fixtures/bom-1.6.schema.json`).

---

## How It Works

```
┌────────────────────────────────────────────────────────┐
│                      Input Layer                       │
│  Source Code (.py/.java/.go) | Cloud JSON | PCAP       │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                    Scanning Engine                     │
│  - Static Regex & AST Heuristics                       │
│  - Same-File Constant Resolution                       │
│  - AWS ELB Policy Expansion (data/elb_policies.json)   │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                      Risk Engine                       │
│  - Shor / Grover Threat Evaluation                     │
│  - NIST Standards Mapping (FIPS 203 / 204 / 205)       │
└──────────────────────────┬─────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
┌───────▼──────────────┐            ┌─────────▼──────────────┐
│   CBOM Serializer    │            │  Streamlit Dashboard   │
│  CycloneDX 1.6 JSON  │            │  Hygiene/Posture UI    │
│  Deterministic Refs  │            │  Plotly Donut Chart    │
└──────────────────────┘            └────────────────────────┘
```

1. **Sandboxed File Ingestion**: Uploaded files are isolated into safe temporary subdirectories without executing code.
2. **Same-File Constant Resolution**: Resolves variable assignments (e.g. `KEY_LEN = 32`, `iterations = 600000`, `b"..."` literals) within the same file to deduce key bit lengths.
3. **ELB Policy Mapping**: Maps AWS `SslPolicy` names (e.g. `ELBSecurityPolicy-2016-08`) to underlying cipher suites and TLS versions using verified AWS policy lookup tables.
4. **CBOM Serializer (`scanner/cbom.py`)**: Converts canonical findings into CycloneDX 1.6 components with cryptographic properties and evidence trails.
5. **Interactive UI (`dashboard.py`)**: Decouples hygiene metrics from search filters; renders dark-themed Plotly charts, risk tier distribution, and filterable tables.

---

## Limitations

* **Static Heuristics**: Uses regex pattern matching and structural heuristics rather than full inter-procedural taint analysis or cross-file symbol dataflow tracking.
* **Same-File Constants Only**: Key lengths and iterations defined in external modules, imported configuration files, or environment variables cannot be statically inferred.
* **Cloud Posture Scope**: Specifically models AWS KMS, Elastic Load Balancing, and ACM certificate dumps; other AWS services and multi-cloud providers (GCP, Azure) are not currently mapped.
* **Network Scanner Status**: The TShark-based network capture dissector currently resides on the `origin/network_scanner` branch and is not yet merged into the main application.

---

## Team

TODO: add team member names

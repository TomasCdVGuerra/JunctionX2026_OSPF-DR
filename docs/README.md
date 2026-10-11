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

*(Note: The command-line interface (`main.py`) is temporarily disabled while cloud and network scan pipelines are unified; the primary supported interface is the interactive Streamlit dashboard).*

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

### Dual-Axis Risk Model (Quantum Risk vs. Classical Risk)
QuantumTrace evaluates all cryptographic assets along two distinct, independent security axes:

* **Quantum Risk**: Future exposure to quantum attacks:
  * **Shor's algorithm**: Breaks public-key cryptography (factoring and discrete logarithms: RSA, ECC, DH). Classified as **Critical**.
  * **Grover's algorithm**: Effectively halves symmetric key strength (AES-128 halved to 64 bits $\rightarrow$ **Medium**; AES-256 halved to 128 bits $\rightarrow$ **Safe**).
* **Classical Risk**: Current pre-quantum security strength:
  * Primitives broken by practical pre-quantum cryptanalysis (**MD5**, **SHA-1**, **DES**, **AES-ECB**) are **Critical**.
  * Parameter sizes deprecated pre-quantum (**RSA-1024**) are **Medium**.
  * Robust pre-quantum primitives (**RSA-2048**, **AES-GCM**, **SHA-256**) are **Safe**.

**Why can an algorithm have different ratings on each axis?**
* **RSA-2048**: `Quantum Risk = Critical` (broken by Shor's algorithm; must migrate to PQC) while `Classical Risk = Safe` (provides ~112 bits of classical security; not broken today).
* **AES-128-GCM**: `Quantum Risk = Medium` (halved to ~64 bits quantum security) while `Classical Risk = Safe` (128 bits pre-quantum security).
* **MD5 / SHA-1**: `Quantum Risk = Critical` and `Classical Risk = Critical` (classically broken).

*(Note: The CBOM serializer preserves classical risk as the standard CycloneDX property `cryptotrace:classicalRisk` alongside `cryptotrace:riskRating`).*

---

## Scoring Model: Hygiene, Risk Exposure & Posture Status

The dashboard exposes the centralized risk and reporting engine (`scanner/report.py` and `scanner/risk.py`). All executive metrics are computed from the **complete active scan inventory**, while search, source, and risk-tier filters apply strictly to detailed views.

### 1. Quantum Risk Score (`0.00–100.00 / 100`)
$$\text{Quantum Risk Score} = \frac{\text{Critical} \times 1.0 + \text{Medium} \times 0.3}{\text{Total Assets}} \times 100$$
* A centralized exposure score reflecting organizational vulnerability to quantum cryptanalysis.
* Critical assets contribute full weight ($1.0$), Medium assets contribute partial weight ($0.3$), Safe and Unknown assets contribute $0.0$.
* For an inventory with 32 Critical and 11 Safe findings (43 total):
  $$\frac{32 \times 1.0 + 0 \times 0.3}{43} \times 100 = 74.42 / 100$$

### 2. Crypto Hygiene Score (`0–100`)
$$\text{Crypto Hygiene} = \max\left(0, \operatorname{int}\left(100 - \frac{\text{Critical} \times 100 + \text{Medium} \times 30}{\text{Total Assets}}\right)\right)$$
* Measures overall proportion of healthy cryptographic assets across the entire inventory.
* Penalizes **100 points per Critical** and **30 points per Medium** finding, normalized over all assets.

### 3. Posture Status
* **🚨 FAILING**: Critical quantum vulnerabilities present (`Critical > 0`).
* **⚠️ AT_RISK**: Medium quantum vulnerabilities present without Critical findings (`Medium > 0`).
* **✅ SECURE**: All inventoried cryptography is quantum-safe (`Critical == 0` and `Medium == 0` with findings present).
* **ℹ️ NO_DATA**: No cryptographic components discovered (`Total == 0`).

> **Filter Independence**: Executive metrics (Quantum Risk Score, Crypto Hygiene, Posture Status, and overall counts) always reflect the full active scan. Filter and search bars dynamically adjust the detailed findings table, donut chart, and displayed finding inspector.


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

## Comandos para Python Environment (criar pela primeira vez):
1. python -m venv .venv (ou py -3.13 -m venv .venv se tiverem versões diferentes desta)

2. Ativar o ambiente (escolher o comando com base no OS/terminal):
    - Windows (PowerShell): .venv\Scripts\Activate.ps1 
    - (Git Bash): source .venv/Scripts/activate
    - Linux / macOS: source .venv/bin/activate

3. Instalar as bibliotecas pretendidas (com pip install ou python -m pip install)

4. python -m pip freeze > requirements.txt (voltar a fazer isto sempre que instalar ou atualizar bibliotecas)

## Comandos para iniciar o Python Environment (em sessões futuras):
1. Ativar o ambiente (conforme o OS indicado acima).
2. (Opcional) python -m pip install -r requirements.txt (Nota: Só é necessário executar este passo se tiver mudados de computador, clonado o projeto do Git novamente ou se outra pessoa no projeto tiver adicionado novas bibliotecas ao ficheiro requirements.txt).

# Correr testes iniciais:
- python.exe -m pytest tests/test_phase0_contract.py -q

# Overview
<!-- Explain the purpose of QuantumTrace: a multi-source cryptographic scanner designed for the JunctionX Lisbon 2026 PQC migration challenge to discover quantum-vulnerable cryptography across source code, AWS cloud posture exports, and PCAP captures, outputting an official CycloneDX 1.6 CBOM. -->

# Install
<!-- Provide installation instructions including Python 3.12 virtual environment creation and installing dependencies via pip install -r requirements.txt. -->

# Run
<!-- Provide CLI execution commands for full end-to-end scanning (python main.py --all), running the Streamlit dashboard (streamlit run dashboard.py), executing unit/integration tests with pytest, and running the automated run.sh script. -->

# Example output
<!-- Show sample terminal output featuring the Rich table summary, quantum risk score breakdown (Critical, Medium, Safe), and snippets from the exported CycloneDX 1.6 CBOM JSON. -->

# How it works
<!-- Describe the scanning architecture: static regex pattern matching with same-file constant resolution for source code (Python, Java, Go), AWS JSON configuration parsing (KMS, ALB with ELB policy mapping, ACM), pure-Python PCAP parsing for TLS handshake cipher suites, and risk evaluation against NIST PQC standards (FIPS 203, 204, 205). -->

# Limitations
<!-- Document known boundaries: static analysis heuristics rather than full AST dataflow/taint tracking, same-file constant resolution rather than cross-file symbol resolution, and offline schema validation scope. -->

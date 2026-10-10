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

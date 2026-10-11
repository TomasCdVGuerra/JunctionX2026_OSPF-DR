## Arranque recomendado: um comando

Com Python 3.13 instalado, executar `py -3.13 run.py` em Windows ou
`python3.13 run.py` em Linux/macOS. O script cria/reutiliza a venv, instala
requirements.txt, verifica dependências e inicia a dashboard. Não exige ativação.

`--setup` prepara sem abrir a interface; `--test` executa a suite completa;
`--require-tshark` exige disponibilidade real de TShark para a demo de PCAP.
run.py é o único ponto de entrada de instalação e arranque nos três sistemas.

### Testes depois do arranque automático

O `run.py` instala também o pytest na `.venv`, mas não ativa o ambiente no
terminal que o iniciou. Um comando `pytest` ou `python -m pytest` nesse
terminal pode usar outro Python, sem as dependências do projeto.

Não é necessário reinstalar requirements. Executar:

```powershell
# Windows
py -3.13 run.py --test
```

```bash
# Linux / macOS
python3.13 run.py --test
```

Para executar testes específicos com `python -m pytest`, ativar primeiro a
`.venv` usando os comandos da secção seguinte. A ativação aplica-se apenas
ao terminal atual.

## Configuração manual alternativa
1. python -m venv .venv (ou py -3.13 -m venv .venv se tiverem versões diferentes desta)

2. Ativar o ambiente (escolher o comando com base no OS/terminal):
    - Windows (PowerShell): .venv\Scripts\Activate.ps1 
    - (Git Bash): source .venv/Scripts/activate
    - Linux / macOS: source .venv/bin/activate

3. Instalar as dependências partilhadas: python -m pip install -r requirements.txt

4. Ao acrescentar uma dependência, editar requirements.txt conscientemente e comunicar a alteração à equipa. Não substituir o ficheiro com pip freeze do ambiente pessoal. Todos devem usar Python 3.13. O ficheiro fixa versões diretas e transitivas obtidas num ambiente limpo validado; não inclui hashes. Após alterar dependências, repetir instalação limpa, pip check e testes, atualizando o snapshot com as dependências necessárias.

## Comandos para iniciar o Python Environment (em sessões futuras):
1. Ativar o ambiente (conforme o OS indicado acima).
2. (Opcional) python -m pip install -r requirements.txt (Nota: Só é necessário executar este passo se tiver mudados de computador, clonado o projeto do Git novamente ou se outra pessoa no projeto tiver adicionado novas bibliotecas ao ficheiro requirements.txt).

# Correr testes iniciais:
- python.exe -m pytest tests/test_phase0_contract.py -q

# Validação completa e demo:
- Sem ativar o ambiente: `py -3.13 run.py --test` em Windows ou `python3.13 run.py --test` em Linux/macOS.
- Os dois comandos seguintes pressupõem a `.venv` ativada:
- python -m pytest -q (inclui os testes em scanner/network_scanner/tests)
- python -m streamlit run dashboard.py
- O TShark é um executável externo; instalar Wireshark/TShark para análises reais de PCAP.
- Consultar [DEMO.md](DEMO.md) para os inputs e resultados esperados.

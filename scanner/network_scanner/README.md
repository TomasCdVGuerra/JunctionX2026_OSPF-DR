# Executar e testar o network scanner

Executar os comandos abaixo em **PowerShell, na raiz do projeto**.
O ponto de entrada é `scanner.network_scanner.pcap_scanner.scan(path)`:
recebe o caminho de uma captura e devolve os resultados avaliados de TLS,
SSH e tráfego em texto claro, com as respetivas evidências.

## 1. Preparar o ambiente

É necessário Python e o executável TShark, normalmente instalado com o
Wireshark. O projeto usa Python 3.13; a execução também foi validada em 3.14.

Se ainda não existir um ambiente `.venv`, criar um:

```powershell
python -m venv .venv
```

Instalar as dependências do projeto e dos testes de cobertura:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r scanner/network_scanner/tests/requirements.txt
```

Os comandos usam diretamente o Python da `.venv`, sem precisar de a ativar.
O TShark é instalado separadamente; o parser procura-o no `PATH` e nas
pastas habituais do Wireshark. Para indicar outra instalação:

```powershell
$env:TSHARK_PATH = 'C:\caminho\para\tshark.exe'
```

Confirmar que o executável é encontrado:

```powershell
.\.venv\Scripts\python.exe -B -c "from scanner.network_scanner.parser.tshark_parser import find_tshark_binary; print(find_tshark_binary())"
```

## 2. Executar com a network.pcap

Copiar o bloco completo para o PowerShell. Este chama `pcap_scanner.scan()`
com a captura existente e guarda todos os resultados em JSON:

```powershell
@'
import json
from collections import Counter
from pathlib import Path

from scanner.network_scanner.pcap_scanner import scan

capture = Path("support-materials/network-capture/network.pcap")
findings = scan(capture)

output = Path(".cache/network-pcap-validation/findings.json")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps([finding.to_dict() for finding in findings], ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)

print(f"Resultados: {len(findings)}")
print(f"Evidencias: {sum(len(finding.evidence) for finding in findings)}")
print(f"Observacoes: {dict(Counter(finding.observation for finding in findings))}")
print(f"JSON: {output.resolve()}")
'@ | .\.venv\Scripts\python.exe -B -
```

Na captura fornecida, validada com TShark 4.4.6, o resultado esperado é:

```text
Resultados: 2419
Evidencias: 2543
Observacoes: {'advertised': 1734, 'negotiated': 609, 'observed': 76}
```

Abrir `.cache/network-pcap-validation/findings.json` no editor para consultar
os algoritmos, riscos, recomendações e evidências. Cada evidência identifica
o ficheiro e o pacote de origem; o campo `matched_snippet` contém o contexto
em JSON, incluindo a ligação, os endereços, as portas e os identificadores.
Há vários resultados por pacote, porque uma cifra pode envolver várias
primitivas criptográficas.

Para analisar outra captura, alterar apenas o valor de `capture` no bloco.

## 3. Testar o coordenador

Os testes do coordenador usam metadados controlados e verificam a combinação
dos protocolos, os riscos, a preservação das evidências e os erros do parser:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q scanner/network_scanner/tests/test_pcap_scanner.py
```

Para testar a leitura de capturas pelo TShark real, incluindo a `network.pcap`:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q scanner/network_scanner/tests/test_parser_integration.py
```

## 4. Testar toda a camada de rede com cobertura

Inclui parser, mapper, adapter, coordenador, avaliação de risco e os três
analysers. A configuração exige 100% de cobertura de linhas e ramificações:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -c scanner/network_scanner/tests/pytest-parser.ini
```

O resultado deve terminar sem falhas. Se os testes de integração aparecerem
como `SKIPPED` por falta de TShark, a leitura da captura real ficou por validar.

O relatório de cobertura fica em `htmlcov/parser/index.html`; abrir esse
ficheiro num navegador. O detalhe dos casos está em [tests/README.md](tests/README.md).

## Interpretação dos resultados

- `advertised`: algoritmo anunciado como opção; não prova utilização.
- `negotiated`: seleção registada em TLS ou inferida das propostas SSH.
  No SSH, a inferência tem confiança média e evidências de ambos os participantes.
- `observed`: protocolo diretamente observado, como um banner SSH ou HTTP sem TLS.
- `unknown`: faltam parâmetros para avaliar esse risco; não equivale a um resultado seguro.

O requisito de descoberta de rede centra-se em TLS Hello; SSH e cleartext
são funcionalidades adicionais. DNS fica fora do âmbito. A captura fornecida
não permite confirmar certificados TLS ou a conclusão dos handshakes.

## Resolver erros de execução

- `ModuleNotFoundError: scanner`: executar os comandos na raiz do projeto.
- `PcapParserError` sobre TShark: instalar o executável ou corrigir `TSHARK_PATH`.
- `PcapParserError` sobre ficheiro inexistente: confirmar o caminho de `capture`.
- Erro sobre `pytest_cov` ou opções `--cov`: instalar também
  `scanner/network_scanner/tests/requirements.txt` com o Python da `.venv`.

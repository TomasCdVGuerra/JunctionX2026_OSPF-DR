# Testes do parser de rede

Executar os comandos na raiz do projeto, em PowerShell.

## Preparar

O ambiente precisa de pytest e pytest-cov. Para instalar no ambiente existente:

```powershell
.\.venv\Scripts\python.exe -m pip install "pytest>=8,<10" -r scanner/network_scanner/tests/requirements.txt
```

Os testes de integração usam o TShark instalado com Wireshark. O parser procura
o executável no PATH e nos diretórios habituais. Para uma instalação diferente:

```powershell
$env:TSHARK_PATH = 'C:\caminho\para\tshark.exe'
```

## Correr todos os testes do parser com cobertura

```powershell
.\.venv\Scripts\python.exe -B -m pytest -c scanner/network_scanner/tests/pytest-parser.ini
```

Esta configuração seleciona `test_pcap_scanner.py` e `test_parser_*.py`, exige
100% de cobertura combinada de linhas e ramificações do `tshark_parser.py`
e do adaptador `model_adapter.py`,
e trata avisos Python como erros. Um teste falhado ou cobertura inferior faz
o comando terminar com erro. Não desativa testes de outros módulos na suite global.

Relatórios gerados na raiz do projeto:

- `htmlcov/parser/index.html`: relatório navegável por ficheiro e linha.
- `htmlcov/parser/coverage.json`: contagens de linhas e ramificações.

O terminal distingue `PASSED`, `FAILED`, `SKIPPED` e `XFAIL`. Testes de integração
saltados por falta de TShark não representam uma validação da captura real.
Uma regressão conhecida marcada `xfail(strict=True)` continua a documentar um
defeito: se passar inesperadamente, o comando falha para exigir a revisão da marca.

## Casos cobertos

- Descoberta do executável por configuração, PATH e instalações Windows/macOS.
- Caminhos com espaços, ficheiros ausentes, timeouts, permissões e erros TShark.
- JSON inválido, resposta vazia, estrutura de resposta inválida e avisos do processo.
- Versões TLS, ClientHello/ServerHello, HelloRetryRequest, grupos e cifras,
  metadados IPv4/IPv6 e campos opcionais ausentes.
- Listas SSH em CSV e identificação conservadora de cliente/servidor.
- Protocolos em texto claro e negativos para portas comuns sem prova de protocolo,
  PostgreSQL SSL/GSSENC e SMTP STARTTLS.
- Captura fornecida, formatos PCAP/PCAPNG e capturas inválidas ou truncadas.

Cobertura de 100% significa que todas as linhas e ramificações medidas foram
executadas. Não prova que todas as combinações possíveis de tráfego estão corretas.

## Defeitos existentes expostos pelos testes

Cinco casos de extração estão marcados
como `xfail(strict=True)` porque demonstram estes comportamentos incorretos:

- ClientHello perde versões desconhecidas da extensão `supported_versions`.
- ServerHello com versão selecionada desconhecida é apresentado como TLS 1.2
  quando o campo `legacy_version` contém `0x0303`.
- Vários ServerHello no mesmo pacote são achatados numa única entrada ambígua.
- Pedidos e respostas HTTP decifrados pelo TShark dentro de TLS são classificados
  como tráfego sem cifra (dois casos).

Para uma auditoria em que estes defeitos também fazem o comando falhar:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -c scanner/network_scanner/tests/pytest-parser.ini --runxfail
```

`xfail` não significa aprovação. Esta opção executa as mesmas asserções sem
aceitar falhas conhecidas. A marca estrita exige revisão se uma futura correção
fizer um caso passar.

## Formato de saída partilhado com models.py

O parser disponibiliza três interfaces:

- `parse_network_pcap(path)`: metadados brutos TLS/SSH/cleartext para inspeção.
- `scan(Path(path))`: lista de objetos `CryptoFinding`, validados por Pydantic,
  com `Evidence` por pacote. Os riscos mantêm o valor inicial `unknown`.
- `parse_network_json(path)`: texto JSON contendo uma lista no formato de
  `CryptoFinding.to_dict()`, com enums serializados e campos `None` omitidos.

Os testes `test_parser_models.py` verificam a conversão, proveniência, distinção
entre propostas e seleções, parâmetros desconhecidos, serialização e validação
de volta para os modelos. Não chamam os analisadores ainda por implementar.

Para executar apenas os testes unitários do parser e da conversão:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -c scanner/network_scanner/tests/pytest-parser.ini --ignore=scanner/network_scanner/tests/test_parser_integration.py
```

Para inspecionar o primeiro resultado JSON da captura do repositório:

```powershell
.\.venv\Scripts\python.exe -B -c "import json; from scanner.network_scanner.parser.tshark_parser import parse_network_json; r = json.loads(parse_network_json('support-materials/network-capture/network.pcap')); print(json.dumps(r[0] if r else {}, ensure_ascii=False, indent=2))"
```

## Suite global

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q
```

A suite global inclui também os testes dos analisadores. Na verificação desta
tarefa, a recolha ficou bloqueada porque `test_ssh_analyzer.py` importa
`analyze_cleartext`, mas `cleartext_analyzer.py` está vazio. O ficheiro
`ssh_analyzer.py` também ainda não disponibiliza a implementação necessária.
Esses módulos requerem implementação, independentemente da cobertura do parser.

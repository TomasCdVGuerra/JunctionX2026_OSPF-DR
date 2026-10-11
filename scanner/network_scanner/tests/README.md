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

## Correr os testes de rede com cobertura

```powershell
.\.venv\Scripts\python.exe -B -m pytest -c scanner/network_scanner/tests/pytest-parser.ini
```

Esta configuração seleciona `test_pcap_scanner.py`, `test_parser_*.py`,
`test_algorithm_mapper.py`, `test_risk_assessment.py`, `test_cleartext_analyzer.py`,
`test_tls_analyzer.py` e `test_ssh_analyzer.py`.
Exige 100% de cobertura combinada de linhas e ramificações do `tshark_parser.py`,
do adaptador `model_adapter.py`, do mapper `algorithm_mapper.py` e dos módulos
`Analyser/risk_assessment.py`, `Analyser/cleartext_analyzer.py`,
`Analyser/tls_analyzer.py` e `Analyser/ssh_analyzer.py`.
Também trata avisos Python como erros. Um teste falhado ou cobertura inferior faz
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
- Política de risco quântico e clássico, parâmetros desconhecidos, justificação
  e recomendação, sem depender da extração de protocolos.
- Análise de cleartext com evidência sanitizada e preservação dos metadados.
- Análise TLS com distinção entre algoritmos anunciados e selecionados,
  parâmetros desconhecidos e regras de risco por versão do protocolo.
- Análise SSH com propostas anunciadas e inferência conservadora da seleção
  por ligação, sem confirmar a conclusão do handshake.

Cobertura de 100% significa que todas as linhas e ramificações medidas foram
executadas. Não prova que todas as combinações possíveis de tráfego estão corretas.

## Defeitos existentes expostos pelos testes

Um caso de extracao esta marcado
como `xfail(strict=True)` porque demonstram estes comportamentos incorretos:

- Vários ServerHello no mesmo pacote são achatados numa única entrada ambígua.

Pedidos e respostas HTTP descodificados dentro de TLS ja sao excluidos dos
resultados cleartext. Os testes verificam cada sinal de transporte TLS.

ClientHello preserva versoes desconhecidas validas em `supported_versions`,
mantendo a ordem e excluindo GREASE e identificadores invalidos.
ServerHello preserva a versao selecionada desconhecida; a selecao tem
prioridade sobre os campos legados.

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
de volta para os modelos. A avaliação de risco tem testes próprios nos analisadores.

Para executar os testes unitários de rede sem a integração TShark:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -c scanner/network_scanner/tests/pytest-parser.ini --ignore=scanner/network_scanner/tests/test_parser_integration.py
```

Para inspecionar o primeiro resultado JSON da captura do repositório:

```powershell
.\.venv\Scripts\python.exe -B -c "import json; from scanner.network_scanner.parser.tshark_parser import parse_network_json; r = json.loads(parse_network_json('support-materials/network-capture/network.pcap')); print(json.dumps(r[0] if r else {}, ensure_ascii=False, indent=2))"
```

## Separação entre extração e análise

`algorithm_mapper.py` mantém os registos TLS/SSH, a decomposição em primitivas e os
helpers de contexto/evidência. Não decide os riscos dos algoritmos.
`model_adapter.py` transforma metadados em findings com riscos `unknown`,
sem chamar a política de análise.

`Analyser/risk_assessment.py` contém `assess_primitive()` e `make_finding()`:
o primeiro avalia as primitivas e o segundo cria um finding com essa avaliação,
ou com uma avaliação explícita fornecida pelo analisador. Os analisadores cleartext,
TLS e SSH reutilizam esse módulo para aplicar a política comum. As regras que
dependem do protocolo ficam no respetivo analisador.
`enrich_finding()` devolve uma cópia avaliada de um finding existente,
preservando os campos da observação, a localização e o contexto da evidência,
e preenchendo a justificação do risco.

Para executar apenas os testes do mapper e da camada de análise:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q scanner/network_scanner/tests/test_algorithm_mapper.py scanner/network_scanner/tests/test_risk_assessment.py scanner/network_scanner/tests/test_cleartext_analyzer.py scanner/network_scanner/tests/test_tls_analyzer.py scanner/network_scanner/tests/test_ssh_analyzer.py
```

## Testes do analisador cleartext

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q scanner/network_scanner/tests/test_cleartext_analyzer.py
```

`analyze_cleartext(entries, path)` recebe as entradas de `detect_cleartext_traffic`
e devolve protocolos observados com risco clássico `critical`, risco quântico
`unknown`, justificação e recomendação. A evidência usa JSON com pacote e
endpoints, excluindo credenciais do host HTTP, URI e payload.

Estes testes verificam a classificação, a privacidade da evidência, entradas
vazias ou sem protocolo válido e a preservação dos metadados originais.

## Testes do analisador TLS

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q scanner/network_scanner/tests/test_tls_analyzer.py
```

`analyze_tls(entries, path)`, em `Analyser/tls_analyzer.py`, recebe as entradas
TLS extraídas pelo parser e devolve uma lista de `CryptoFinding` com riscos,
justificação, recomendação e evidência. Reutiliza a conversão do adapter e a
política comum para avaliar as primitivas identificadas e acrescenta a regra
específica para a versão TLS.
SSL 3.0, TLS 1.0 e TLS 1.1 recebem risco clássico `critical`. Nas restantes
versões, o protocolo isolado conserva riscos `unknown`; os algoritmos são
avaliados separadamente.

As propostas do cliente continuam `advertised`; uma seleção do servidor é
`negotiated`. A avaliação conserva parâmetros desconhecidos e a proveniência
do pacote, sem alterar as entradas recebidas. Uma cifra TLS 1.3 não fornece
por si só o grupo de troca de chaves ou o algoritmo de autenticação da sessão.
HelloRetryRequest é excluído, tal como na conversão existente do adapter.

## Testes do analisador SSH

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q scanner/network_scanner/tests/test_ssh_analyzer.py
```

`analyze_ssh(entries, path)`, em `Analyser/ssh_analyzer.py`, recebe as entradas
SSH extraídas pelo parser. Avalia os algoritmos anunciados e pode acrescentar
resultados de seleção inferida ao relacionar propostas de cliente e servidor
na mesma ligação. A escolha segue a preferência do cliente entre as opções
comuns de cada categoria e direção.

A inferência exige exatamente uma proposta de cada papel no mesmo stream,
papéis explicitamente identificados e endpoints completos em sentidos opostos.
Entradas de banner sem listas de algoritmos não contam como propostas.
A seleção inferida usa `observation="negotiated"` e `confidence="medium"`.
A evidência explica a inferência; duas propostas compatíveis não confirmam
que o handshake tenha terminado. Sem identificação fiável da ligação ou dos
papéis, ou com várias propostas e rekeys no mesmo stream,
mantêm-se apenas os algoritmos anunciados. Com uma cifra AEAD, não se cria
um MAC independente como algoritmo negociado.

Os analisadores são chamadas explícitas de avaliação. `parser.scan()` continua
a produzir findings com riscos `unknown`, preservando o contrato de extração.

## Suite global

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q
```

A suite global inclui os testes dos três analisadores implementados em
`scanner.network_scanner.Analyser`. Os testes SSH importam o módulo desse
diretório, alinhado com a localização da implementação.

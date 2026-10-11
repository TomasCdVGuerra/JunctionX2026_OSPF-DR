# QuantumTrace: validação e demo

## Preparação

Usar Python 3.13, ativar `.venv` e executar:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m streamlit run dashboard.py
```

Para PCAP real, instalar Wireshark/TShark. A deteção procura `TSHARK_PATH`,
`PATH` e as pastas habituais do Wireshark. Os testes unitários de rede usam
metadata controlada; passar esses testes não substitui testar TShark real.

## Inputs da demo

Limpar a análise ativa e carregar conjuntamente:

- Os três JSON em `support-materials/cloud-posture`.
- Os oito ficheiros `main.go` em `support-materials/sample-repos/go`, sem renomear os ficheiros.
- `support-materials/network-capture/network.pcap`.

Os uploads com o mesmo nome são isolados em pastas temporárias diferentes.
Para distinguir os vários `main.go`, consultar o snippet e a regra: o dashboard
mostra `#Input ID main.go`, ligado à entrada em File scan coverage. A evidência
preserva o nome original, sem inventar a pasta do projeto.

Deixar todos os filtros selecionados e a pesquisa vazia.

| Origem | Findings esperados nos exemplos atuais |
|---|---:|
| Cloud | 99 |
| Go | 19 |
| Rede | 2419 |
| Total | 2537 |

Estas contagens foram verificadas com o TShark instalado no PC de desenvolvimento.
Outras versões de TShark podem extrair metadata diferente. As contagens são
observações criptográficas, não sessões, recursos únicos ou uma medição de precisão.

Python e Java já têm scanners reais integrados. Para alargar esta demo, carregar
também os oito `.py` e os oito `.java` nas respetivas pastas de `sample-repos`.
Os exemplos atuais produzem 13 findings Python e 14 Java, somando 2564 ao
inventário conjunto. Estes scanners reconhecem APIs suportadas, sem análise
completa de fluxo de dados; um resultado vazio não prova ausência de criptografia.

## Percurso de apresentação

1. Mostrar os três tipos de origem e a evidência: JSON Path para Cloud,
   Line Number para Go e Packet Number para Rede.
2. Explicar as duas avaliações: RSA pode ser crítico no eixo quântico sem ser
   crítico no eixo clássico. As colunas da tabela e do CSV chamam-se
   Quantum Risk e Classical Risk. Unknown significa avaliação por resolver.
   Mostrar também Quantum Risk Score e Quantum Assessment Coverage: o score
   mede exposição apenas entre findings avaliados; com cobertura zero aparece N/A.
   Crypto Hygiene mede avaliação clássica e é uma métrica diferente.
3. Selecionar Classical risk = Critical, mantendo todos os riscos quânticos:
   devem aparecer 122 findings na análise conjunta, incluindo tráfego sem encriptação.
4. Repor todos os riscos e selecionar Observation = negotiated: a captura
   tem 609 seleções identificadas ou inferidas. Isto não prova conclusão da sessão.
5. Mostrar referências e recomendações. Referências NIST são publicações técnicas,
   não certificação; nos híbridos, uma referência pode cobrir apenas um componente.
   Selecionar uma linha da tabela compacta para abrir avaliação, ação recomendada
   e evidência. Full table permite consultar todas as colunas anteriores.
   Cada eixo mostra o significado do nível e a justificação. Unknown destaca
   dados em falta e os problemas já conhecidos, como CBC numa suite incompleta.
   Em código, consultar Library / API. Em Java é a API identificada, não o provider
   da implementação. O CBOM preserva esta informação e inclui cryptoProperties nativas.
6. Confirmar que as métricas superiores mantêm o inventário completo quando os
   filtros mudam. O gráfico, tabela e CSV acompanham os filtros.
7. Repor todos os filtros e descarregar CSV (2537 linhas) e CBOM CycloneDX 1.6.
   O CBOM contém o inventário completo, independentemente dos filtros da tabela.
   Selecionar uma linha não restringe o CSV: exporta todas as linhas filtradas e
   todos os campos da tabela completa.

## Limites a explicar

Mostrar a ordenação por prioridade, que considera ambos os eixos, e abrir
Priority actions para consultar recomendações agrupadas e exportar o CSV.
Abrir File scan coverage para distinguir deteções, ausência de deteções e
falhas. Para demonstrar isolamento de erros, carregar um JSON inválido com
um export cloud válido: os findings do válido continuam disponíveis.

Input Scan Status deve mostrar Partial nesse cenário, mesmo que os findings
do ficheiro válido sejam Safe. FAILING continua visível se houver risco crítico.
Repetir com dois ficheiros do mesmo nome e confirmar Input ID na tabela e CSV.

- Advertised é uma capacidade oferecida; negotiated é uma seleção; observed
  é evidência direta. Não agregar estas categorias como sessões distintas.
- Safe aplica-se apenas aos critérios avaliados, não à segurança integral da aplicação.
- O motor geral avalia Cloud/Go/Python/Java; analisadores de rede preservam decisões específicas
  de TLS/SSH. A harmonização das políticas deve ser revista com a equipa.
- Se TShark falhar, apresentar o erro e resolver o executable/PATH; não tratar
  a ausência de findings como prova de ausência de risco.

## Antes de integrar na main

A referência manual em tests/fixtures/expected_findings.json cobre nove ficheiros
de código e verifica deteção, localização, parâmetros e ambos os riscos.
Não representa uma medição de precisão/recall global.

Executar a suite completa, rever os ficheiros alterados e repetir os uploads
reais. Os colegas que implementam Python/Java devem devolver `CryptoFinding`,
preservar evidência, deixar parâmetros por resolver como `None` e validar
o percurso até ao dashboard e aos exports.

## Ensaio num segundo PC

Este passo exige outro computador; os testes locais não o substituem.

1. Num checkout atualizado, com Python 3.13, executar `run.ps1 -Mode test`
   ou `bash run.sh --test`. Confirmar também `python -m pip check` no ambiente.
2. Instalar TShark separadamente e confirmar que é detetado. Sem TShark,
   os testes offline podem passar e o teste de captura real fica skipped.
3. Iniciar a dashboard e carregar os inputs da demo. Confirmar as contagens
   de inventário, Input Scan Status Complete e evidência de JSON/linha/pacote.
   Complete refere-se ao processamento, não à avaliação de todos os riscos.
4. Repetir com um JSON inválido junto de um válido. Confirmar Partial e
   persistência dos findings válidos. Com nomes repetidos, confirmar Input ID.
5. Aplicar filtros, selecionar um finding e exportar CSV, ações e CBOM.
   Reimportar o CBOM e confirmar identidade e estado de cobertura preservados.
6. Após integrar o workflow no GitHub, confirmar execução bem-sucedida dos
   jobs Windows/Linux. O job Linux exige a validação real com TShark.

Registar sistema operativo, Python, TShark, resultado dos testes e quaisquer
diferenças observadas. As classificações de HMAC/HKDF/PRF SHA-2 na rede agora
permanecem Unknown sem parâmetros suficientes; isso pode aumentar Unknown
sem alterar a contagem total de observações.

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
atualmente mostra o nome original, sem a pasta do projeto.

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

Python e Java ainda não têm implementações neste checkout; usam heurísticas
limitadas, identificadas como fallback. Não os incluir neste cenário de referência.

## Percurso de apresentação

1. Mostrar os três tipos de origem e a evidência: JSON Path para Cloud,
   Line Number para Go e Packet Number para Rede.
2. Explicar as duas avaliações: RSA pode ser crítico no eixo quântico sem ser
   crítico no eixo clássico. As colunas da tabela e do CSV chamam-se
   Quantum Risk e Classical Risk. Unknown significa avaliação por resolver.
3. Selecionar Classical risk = Critical, mantendo todos os riscos quânticos:
   devem aparecer 122 findings na análise conjunta, incluindo tráfego sem encriptação.
4. Repor todos os riscos e selecionar Observation = negotiated: a captura
   tem 609 seleções identificadas ou inferidas. Isto não prova conclusão da sessão.
5. Mostrar referências e recomendações. Referências NIST são publicações técnicas,
   não certificação; nos híbridos, uma referência pode cobrir apenas um componente.
6. Confirmar que as métricas superiores mantêm o inventário completo quando os
   filtros mudam. O gráfico, tabela e CSV acompanham os filtros.
7. Repor todos os filtros e descarregar CSV (2537 linhas) e CBOM CycloneDX 1.6.
   O CBOM contém o inventário completo, independentemente dos filtros da tabela.

## Limites a explicar

- Advertised é uma capacidade oferecida; negotiated é uma seleção; observed
  é evidência direta. Não agregar estas categorias como sessões distintas.
- Safe aplica-se apenas aos critérios avaliados, não à segurança integral da aplicação.
- O motor geral avalia Cloud/Go; analisadores de rede preservam decisões específicas
  de TLS/SSH. A harmonização das políticas deve ser revista com a equipa.
- Se TShark falhar, apresentar o erro e resolver o executable/PATH; não tratar
  a ausência de findings como prova de ausência de risco.

## Antes de integrar na main

Executar a suite completa, rever os ficheiros alterados e repetir os uploads
reais. Os colegas que implementam Python/Java devem devolver `CryptoFinding`,
preservar evidência, deixar parâmetros por resolver como `None` e validar
o percurso até ao dashboard e aos exports.

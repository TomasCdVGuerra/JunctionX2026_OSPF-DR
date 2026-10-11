# QuantumTrace — OSPF-DR

QuantumTrace descobre observações criptográficas em código Python/Java/Go,
exports AWS e capturas de rede. Avalia risco quântico e clássico separadamente,
preserva evidências e exporta CSV e CBOM CycloneDX 1.6.

## Instalação e execução

Todos usam Python 3.13 e as dependências de requirements.txt.

```powershell
# Windows: prepara .venv, instala dependências e inicia o dashboard
.\run.ps1
# Apenas preparar o ambiente
.\run.ps1 -Mode setup
# Preparar o ambiente e executar todos os testes
.\run.ps1 -Mode test
```

```bash
# Linux/macOS: requer python3.13; também aceita .venv existente em Git Bash
bash run.sh --ui
bash run.sh --setup
bash run.sh --test
```

Wireshark/TShark é uma instalação externa necessária apenas para PCAP real.
A deteção procura TSHARK_PATH, PATH e as pastas habituais do Wireshark.
O script verifica a presença do executável; não instala Wireshark.

Para instalação manual, ver [DEV_SETUP.md](DEV_SETUP.md).
A interface suportada é Streamlit. main.py está desativado; a CLI não está
concluída e os scripts não a invocam.

## Cobertura atual

| Origem | Implementação | Evidência |
|---|---|---|
| Python | AST; imports/aliases e construções suportadas | Linha, snippet, regra |
| Java | Tokenização; APIs suportadas e contexto local | Linha, snippet, regra |
| Go | Padrões e contexto local suportados | Linha, snippet, regra |
| AWS | Exports KMS, ACM e listeners ELB; catálogo de policies | JSON Path e recurso original |
| Rede | TShark real integrado; TLS, SSH e tráfego sem encriptação | Pacote e contexto de protocolo |

Quando resolvida, a coluna Library / API identifica o namespace da biblioteca
ou API. Uma API Java não identifica o provider JCA efetivo, nem a versão da
biblioteca. Dados desconhecidos não são inventados.

Erros de leitura/parsing Python/Java chegam ao dashboard. Na análise dos
exemplos, ficheiros válidos continuam a ser processados e as falhas são avisadas.
A análise Java usa um tokenizer, não um compilador: não valida toda a sintaxe Java.

## Avaliação e métricas

- **Quantum Risk:** Critical para primitivas vulneráveis a Shor; Medium para
  força insuficiente segundo os critérios quânticos adotados; Safe para os
  critérios avaliados; Unknown quando faltam parâmetros/contexto.
- **Classical Risk:** avaliação independente. AES/ECB é Critical; RSA-1024 é
  Critical; RSA-2048 pode ser Safe no critério de tamanho e Critical no eixo quântico.
- Hashes dependem da finalidade: SHA-256 como digest é Medium no critério de
  colisão quântica; SHA-384/512 são Safe nesse critério. HMAC/PBKDF2 não recebem
  Safe automaticamente sem informação suficiente sobre chave/password.
- **Quantum Risk Score:** `100 × (Critical + 0.3 × Medium) / avaliados`, em que
  avaliados exclui Unknown. Maior score significa maior exposição.
- **Quantum Assessment Coverage:** `100 × avaliados / total`. Sem cobertura,
  o dashboard apresenta score N/A; o relatório numérico conserva 0 e cobertura 0.
- **Crypto Hygiene:** proporção de segurança clássica verificada, com peso 1
  para Safe e 0.7 para Medium. Unknown e Critical não contribuem para higiene.
  No dashboard fica na secção recolhida Classical assessment details; 100/100
  não significa resiliência quântica nem certificação da aplicação.
- **Posture:** FAILING para Critical em qualquer eixo; AT_RISK para Medium;
  INCOMPLETE para Unknown; SECURE quando todos os critérios avaliados são Safe;
  NO_DATA quando não existem findings.

As métricas superiores usam o inventário completo. Filtros afetam tabela,
gráfico e CSV; o CBOM exporta o inventário completo. As contagens são
observações, não sistemas, recursos ou sessões únicos. Safe não certifica a aplicação.

Cloud e código usam o motor geral; rede preserva avaliações dos analisadores
com contexto de TLS/SSH. Advertised, negotiated e observed têm significados
diferentes; uma oferta ou seleção não prova conclusão da sessão.

## CBOM e referências

O export usa componentes cryptographic-asset e cryptoProperties nativas
para tipos de asset e metadata explícita de operação, modo, parâmetros e
protocolo. Chaves são representadas como related-crypto-material.
Riscos, bibliotecas/APIs, recomendações e evidência completa continuam nas
propriedades cryptotrace:*, preservando compatibilidade com o dashboard.

Não inferimos níveis de certificação, força de segurança ou OIDs a partir
do risco. Parâmetros em falta são omitidos. Referências NIST são publicações
técnicas; não demonstram certificação FIPS nem conformidade da implementação.
O catálogo reconhece parâmetros completos de ML-KEM, ML-DSA e SLH-DSA.
Kyber draft/híbridos não são automaticamente tratados como FIPS 203 completos.

## Validação e demo

```bash
python -m pytest -q
```

A suite inclui validação offline do schema CycloneDX 1.6, integração dos
scanners e testes de regressão. tests/fixtures/expected_findings.json
contém expectativas explicadas para nove ficheiros de código revistos.
Esta amostra não mede precisão/recall globais. Testes de rede com metadata
controlada não substituem uma execução real com TShark.

Ver [DEMO.md](DEMO.md) para uploads, contagens observadas e percurso da demo.

## Limites e evolução

- Resolução de variáveis é limitada; não existe análise completa entre funções/ficheiros.
- A deteção de primitivas não é uma auditoria completa de nonces, passwords,
  chaves hardcoded ou geradores pseudoaleatórios.
- Cobertura Cloud é específica dos exports suportados e das policies do catálogo.
- Um resultado vazio não prova ausência de criptografia.
- requirements.txt tem intervalos de versões; não é um lockfile.
- Falta alargar a referência manual a todos os exemplos e medir omissões/falsos positivos.
- Agrupamento por recurso/sessão, análise entre funções, harmonização adicional
  das políticas e plano de migração priorizado são próximas evoluções.

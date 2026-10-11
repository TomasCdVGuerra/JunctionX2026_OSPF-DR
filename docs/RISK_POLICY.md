# Critérios e diferenças entre scanners

Os níveis são regras de avaliação do projeto. Safe aplica-se aos critérios
avaliados; não certifica a implementação, a aplicação ou uma sessão completa.

| Evidência equivalente | Quantum | Classical |
|---|---|---|
| AES-128-GCM | Medium | Safe |
| AES-256-GCM | Safe | Safe |
| AES-128-CBC | Medium | Medium: rever autenticação, IV e padding |
| AES-ECB, tamanho desconhecido | Unknown | Critical: revela padrões |
| RSA-2048, assinatura | Critical | Safe no critério de tamanho |
| RSA, tamanho desconhecido | Critical | Unknown |
| SHA-256, digest | Medium | Safe |
| SHA-384, digest | Safe | Safe |
| HMAC-SHA-256, sem entropia/tag verificadas | Unknown | Unknown |

`tests/test_risk_policy_consistency.py` compara o motor geral com a política
de rede nestes casos. Não converte capacidades advertised em uso observado.

## Diferenças que dependem do contexto

- RSA-2048 usado para transporte de chaves na rede recebe Classical Medium:
  a revisão inclui ausência de forward secrecy. O tamanho da chave de uma
  assinatura, por si só, recebe Safe no critério de tamanho.
- AES com tamanho válido mas sem modo recebe Safe no critério limitado da
  chave no motor geral. A avaliação de configuração de rede mantém Classical
  Unknown sem modo reconhecido. Ambos os motivos devem ser lidos com o finding.
- Uma versão TLS 1.2/1.3 configurada num catálogo cloud pode cumprir o critério
  de versão. A versão numa captura não estabelece segurança da sessão:
  esse finding permanece Unknown e cifra, grupo e autenticação são separados.
- HMAC/HKDF/PRF com SHA-2 na rede mantêm Unknown sem comprovar qualidade da
  entrada secreta e os parâmetros necessários. O identificador anunciado ou
  selecionado não basta. O tamanho de uma chave também não prova entropia.
- Construções keyed legadas com MD5/SHA-1 mantêm Medium na política de revisão
  de protocolos da rede. Isto não afirma que ataques de colisão ao digest
  quebram automaticamente HMAC. O motor geral exige contexto para avaliar
  a construção completa.
- Hybrids identificados no catálogo de rede avaliam a seleção de primitivas.
  Não garantem autenticação pós-quântica nem conformidade FIPS da implementação.
  Draft Kyber permanece distinguido de ML-KEM.

Novas diferenças devem ter evidência, justificação e teste, sem inferir
parâmetros que o scanner não observou.

## Postura e cobertura de inputs

Posture Status considera os findings descobertos, em ambos os eixos. Input
Scan Status descreve o processamento: Complete, Partial ou Unknown. Falhas,
entradas ignoradas e fallback implicam Partial. Sem registo de análise por
ficheiro, um CBOM antigo apresenta Unknown.

Um finding crítico continua FAILING numa análise parcial. Um inventário Safe
não estabelece segurança dos ficheiros que falharam. Complete significa
que todos os inputs registados foram processados pelos scanners completos;
não significa deteção exaustiva nem cobertura de avaliação quântica de 100%.

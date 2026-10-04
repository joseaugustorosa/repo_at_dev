# Pipeline DevSecOps — decisões e justificativas (Exercício 12)

Arquivo executável: `.github/workflows/security-pipeline.yml`. Equivalente local: `bash scripts/security_gate_local.sh`.

## 1. Visão do fluxo (SDLC → CI/CD)

```
 dev machine        PULL REQUEST (minutos)                       APP EM EXECUÇÃO (PR/main)      STAGING (manual/semanal)     PRODUÇÃO
 ───────────        ──────────────────────────────────────────   ───────────────────────────    ─────────────────────────    ────────────
 pytest local   →   Segredos (Trivy secret)   ┐                  DAST passivo                   DAST autenticado/ativo       monitoramento
 (opcional:         SAST   (Bandit ≥ MEDIUM)  │                  ZAP baseline + API (-S)        ZAP em staging, dados        + SCA semanal
  pre-commit)       SCA    (Trivy + pip-audit)├─► SECURITY       regras FAIL / risco ≥ Médio    fictícios                    (novas CVEs)
                    Testes de segurança       │    GATE          ─────────────────────────      IAST (agente, suíte de
                    (derivados do threat      │   (check         bloqueia o merge               integração) — lacuna
                     model) + OpenAPI audit   │    obrigatório)                                  assumida
                    gate-regression           ┘
```

## 2. Decisão por tipo de ferramenta

| Tipo | Ferramenta escolhida | Quando roda | Por que **nesta** fase | O que cobre do histórico |
|---|---|---|---|---|
| **Segredos** | Trivy (`scanners: secret`) | PR | custo ~zero; um segredo em commit já está no histórico do git — descobrir tarde não adianta | F-02 (segredo JWT fixo) |
| **SAST** (estática) | Bandit `-ll` | PR | não precisa de aplicação rodando; feedback em segundos; a falha ainda é só código | F-03 (SQL por f-string); parte de F-02 |
| **SCA** (dependências) | Trivy `vuln` + `pip-audit` | PR **e** semanal | CVE surge sem nenhum commit; duas bases (Trivy e OSV/PyPI) reduzem falso-negativo | F-08 (25 CVEs no kit) |
| **Testes de segurança** | pytest (197 testes; 25 ameaças) | PR | única camada que enxerga **regra de negócio** (BOLA, papéis, escopo) | F-01, F-04, F-05, F-06, F-07 |
| **Auditoria do contrato** | `scripts/audit_openapi.py` | PR | falha se alguém abrir endpoint sem `security`, corpo aberto, campo interno em resposta | F-01, F-06, F-10 |
| **DAST passivo** | OWASP ZAP baseline + API scan com `-S` | após subir a app (PR/main) | só existe com a aplicação rodando; **passivo** = não ataca, então é seguro em todo PR | F-09, F-11 (headers, CORS, cookies, CSRF) |
| **DAST ativo / autenticado** | ZAP full scan | **staging**, manual/semanal | injeta payloads e pode criar dados/derrubar a app → só em ambiente descartável, **nunca em produção**, com dados fictícios | F-03, F-09 (confirmação), força bruta |
| **IAST** (interativa) | agente (Contrast/Datadog IAST) | QA/staging, durante a suíte de integração | só enxerga o fluxo dado→query *dentro* do processo quando algum teste exercita o caminho; precisa de agente, licença e carga de testes | confirma BOLA/SQLi em tempo de execução |

**Lacuna assumida (IAST).** Não há agente IAST configurado neste projeto; o job está descrito, não implementado. A lacuna é compensada por (a) testes de autorização derivados do threat model e (b) ZAP autenticado — e registrada como R-12.

## 3. Critério do security gate

### Regra

O merge é **bloqueado** quando qualquer item abaixo ocorre:

| # | Condição | Ferramenta |
|---|---|---|
| 1 | **qualquer** teste de segurança falha | pytest |
| 2 | **segredo** detectado (qualquer tipo) | Trivy |
| 3 | achado SAST de severidade **MEDIUM ou maior** | Bandit `-ll` |
| 4 | vulnerabilidade **HIGH/CRITICAL** com correção (Trivy) **ou** qualquer CVE com correção disponível (pip-audit `--strict`) | Trivy / pip-audit |
| 5 | alerta ZAP de regra marcada `FAIL` em `.zap/rules.tsv` **ou** risco ≥ Médio não marcado `IGNORE` | `scripts/zap_report.py gate` |
| 6 | cobertura de testes < 85 % | pytest-cov |
| 7 | auditoria OpenAPI com `FAIL` | `scripts/audit_openapi.py` |

Equivalente em CVSS: **≥ 7,0 bloqueia sempre**; **4,0–6,9 bloqueia se afeta a confidencialidade de dado de saúde** (impacto de negócio 4 — garantido pelos testes de autorização, porque nenhum scanner calcula impacto de negócio); **< 4,0** gera relatório.

### Por que esse limiar (e não o do exemplo da aula)

O exemplo da aula bloqueava só `HIGH` (`bandit -lll`). Rodei o Bandit nas duas versões da aplicação (`evidence/ex12_pipeline/bandit_antes.txt`):

| Critério | Versão vulnerável | Resultado |
|---|---|---|
| `-lll` (somente HIGH) | exit **0** | **a SQL injection passaria** (B608 é *Medium*, confiança *Low*) |
| `-ll` (MEDIUM+) | exit **1** | bloqueada por B608 |

Em um sistema de dado de saúde, SQL injection é a pior classe de falha mesmo sendo "Medium" na escala do scanner. Por isso o corte em MEDIUM — decisão tomada a partir de **evidência do próprio histórico de vulnerabilidades**, não de preferência. Mesmo assim, o SAST pegou **1 de 9** falhas do Ex. 8; as demais exigiram testes de autorização e DAST — daí a pirâmide em camadas.

### O gate é testado

* `gate-regression`: o Bandit **precisa reprovar** a baseline vulnerável; se passar, o job falha (gate frouxo).
* `scripts/ci_gate.py` (decisão final): só `success` libera; `skipped`/`cancelled`/`failure` bloqueiam — testado em `tests/test_ex12_ci_gate.py`.
* `scripts/zap_report.py gate`: testado com *fixture* sintética (identificada como tal).
* Todas as *Actions* são fixadas por **SHA de commit**; há teste que reprova *action* não fixada.

## 4. Priorização das vulnerabilidades (CVSS + impacto de negócio)

`docs/cvss_priorizacao.md` (gerado por `scripts/cvss.py`, calculadora validada contra vetores de referência). Regra: **P0** = CVSS ≥ 9 ou (≥ 7 e impacto ≥ 3); **P1** = CVSS ≥ 7 ou impacto crítico; **P2** = 4–6,9; **P3** = < 4. Exemplo da razão de existir o impacto de negócio: a BOLA de leitura é **CVSS 6,5 (Média) mas P1**, pois expõe prontuário de terceiro.

## 5. Estratégia de testes derivada do threat model

Fonte única: `tests/threat_matrix.py` (25 ameaças → 53 verificações). O teste `test_matriz_de_ameacas_aponta_apenas_para_testes_existentes` impede a matriz de apontar para teste inexistente; `scripts/gen_traceability.py` executa cada um e grava `docs/matriz_ameaca_teste.md`. O teste do Ex. 6 ("não-admin barrado em rota de admin") foi expandido para: JWT forjado/expirado/`alg=none`/outra audiência; BOLA em leitura/escrita/cancelamento e em `GET /patient/{id}`; mass assignment; escalada de papel; token M2M × usuário; replay de MFA; deny-by-default em todas as rotas; credential stuffing; anti-lockout; trilha de auditoria.

## 6. Operação

* **Branch protection (configurar no GitHub):** exigir o check `SECURITY GATE`, ao menos 1 revisão, histórico linear; proibir *push* direto em `main`.
* **Exceções:** achado aceito exige registro em `docs/ex13_risco_residual.md` com responsável e prazo (HIGH/CRITICAL: 7 dias; MEDIUM: 30 dias).
* **Variável opcional `STAGING_URL`:** habilita o job de staging.
* **Segredos no CI:** nenhum. `scripts/bootstrap_env.py` gera segredos aleatórios *no runner*.

## 7. Execução real e limites

* **Executado no GitHub Actions:** [run 37171607254](https://github.com/joseaugustorosa/repo_at_dev/actions/runs/37171607254) — jobs `sast`, `sca-and-secrets`, `tests`, `gate-regression`, `dast-passive` e `security-gate` em `success` (`evidence/ex12_pipeline/actions_run_verde.txt`). O 1º run havia falhado no DAST (script de token dependia de `httpx2`); a correção foi validada pelo run seguinte.
* Os mesmos comandos também rodam localmente (`bash scripts/security_gate_local.sh`) e o ZAP real local está em `evidence/ex13_capstone/zap/`.
* **Ainda depende do dono do repositório:** ligar o *branch protection* na `main` exigindo o check `SECURITY GATE` (sem isso o gate reporta, mas não impede o merge).
* **Não verificado:** se o `replacer` do `Authorization` foi aplicado no scan de API do Actions (artefatos exigem login para baixar). Localmente funcionou (403 de RBAC). Conferir no artefato `zap-api-report`.

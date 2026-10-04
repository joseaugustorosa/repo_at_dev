# Priorização das vulnerabilidades — CVSS v3.1 + impacto de negócio (Exercício 12)

Scores calculados por `scripts/cvss.py` (fórmulas da especificação FIRST CVSS v3.1); os vetores
são avaliação do autor para a versão **antes** das correções — não são scores oficiais do NVD.

## Critério de impacto de negócio (dados de saúde — LGPD art. 5º II e art. 11)

| Nível | Critério |
|---|---|
| **4 — Crítico** | Exposição, alteração ou controle de dados de saúde de **vários pacientes/terceiros** ou de contas administrativas; exige notificação à ANPD/titulares (LGPD art. 48) e pode paralisar a clínica. |
| **3 — Alto** | Compromete sessão/conta de equipe clínica ou a disponibilidade do agendamento; dado de saúde só alcançável com passos adicionais. |
| **2 — Médio** | Facilita ataques ou reprova em auditoria, sem acesso direto a dado de saúde. |
| **1 — Baixo** | Informação técnica sem efeito direto. |

## Regra de prioridade

* **P0** — CVSS ≥ 9,0, **ou** CVSS ≥ 7,0 com impacto ≥ 3 → corrige antes de qualquer release;
* **P1** — CVSS ≥ 7,0, **ou** impacto = 4 (mesmo com CVSS < 7: ex. BOLA de leitura, CVSS 6,5 mas dado de saúde de terceiro);
* **P2** — CVSS 4,0–6,9 · **P3** — CVSS < 4,0.

O CVSS mede gravidade técnica; **não enxerga** o que significa vazar um prontuário. Por isso o impacto de
negócio entra na regra, e por isso as falhas de autorização têm testes que bloqueiam o pipeline *independentemente* de score.

## Tabela (ordenada por impacto de negócio e score)

| Prio | ID | Vulnerabilidade | OWASP | Vetor CVSS 3.1 | Score | Severidade | Impacto de negócio | Correção | Ex. |
|---|---|---|---|---|---|---|---|---|---|
| **P0** | F-01 | Cadastro público aceita `role=admin` (mass assignment) | A01:2021 / API3:2023 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Crítica | Crítico — Qualquer pessoa vira administrador e lê/altera dados de todos os pacientes. | Signup só para admin; `extra='forbid'`; papel validado por Enum | Ex. 9 |
| **P0** | F-02 | Segredo JWT fixo no código/repositório (forja de token) | A02:2021 / A07:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1** | Crítica | Crítico — Token de admin forjado sem credencial; acesso total a dados de saúde. | Segredo via BaseSettings/.env (>= 32 chars); iss/aud/exp/jti obrigatórios; HS256 fixo | Ex. 6/11 |
| **P0** | F-03 | SQL injection na busca de pacientes (query por f-string) | A03:2021 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8** | Alta | Crítico — Dump/alteração de toda a base de pacientes (CPF, telefone), inclusive de outros profissionais. | `select().where()` parametrizado + whitelist do termo + LIKE com autoescape | Ex. 9/11 |
| **P0** | F-04 | BOLA de escrita: PUT/DELETE de consulta de outro profissional | A01:2021 / API1:2023 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.1** | Alta | Crítico — Adulteração do prontuário e cancelamento de consultas alheias (integridade clínica). | Filtro de ownership dentro da query (auth/ownership.py); 404 uniforme | Ex. 9 |
| **P1** | F-05 | BOLA de leitura: prontuário de outro profissional por ID na URL | A01:2021 / API1:2023 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | Média | Crítico — Vazamento de dado de saúde de terceiro (LGPD art. 11, notificação à ANPD) — CVSS 'médio', impacto crítico. | Mesmo filtro de ownership; auditoria de tentativa (object_access_denied) | Ex. 9 |
| **P1** | F-06 | BOLA no mesmo padrão em `GET /patient/{id}` (+ CPF completo) | A01:2021 / API1:2023 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | Média | Crítico — Identificação de pacientes de outro profissional; CPF é identificador forte. | scope_patients() + máscara de CPF no response model | Ex. 9 |
| **P0** | F-08 | Dependências com CVEs conhecidas (FastAPI/Starlette, python-multipart, python-jose) | A06:2021 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **7.5** | Alta | Alto — ReDoS em parsing de formulário público derruba o agendamento (disponibilidade). | Versões atualizadas e fixadas; PyJWT no lugar de python-jose; pip-audit no CI | Ex. 12 |
| **P0** | F-07 | Força bruta no login (sem rate limit nem MFA) | A07:2021 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | **7.4** | Alta | Alto — Tomada de contas de equipe clínica; admin sem 2º fator seria comprometimento total. | 5/min por conta + 20/min por IP (429); bcrypt; MFA TOTP obrigatório para admin | Ex. 6/10 |
| **P2** | F-09 | XSS armazenado na agenda da recepção | A03:2021 | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **5.4** | Média | Alto — Script roda na sessão de quem abre a agenda e pode agir como recepcionista (dados de pacientes). | Whitelist de entrada + autoescape do Jinja2 + CSP sem script + cookie HttpOnly | Ex. 2/9 |
| **P2** | F-10 | Resposta devolve campos internos de auditoria e CPF completo | API3:2023 | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | **4.3** | Média | Médio — Facilita mapeamento do sistema e identificação de usuários por terceiros. | Response models Pydantic com whitelist de campos | Ex. 2 |
| **P2** | F-11 | CORS com curinga e ausência de cabeçalhos de segurança | A05:2021 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | **4.2** | Média | Médio — Reprovação em auditoria de pré-produção; leitura cross-origin por site malicioso. | Allowlist de origens; HSTS, X-Frame-Options, X-Content-Type-Options, CSP | Ex. 10 |

# Mapa da rubrica → onde está demonstrado

Cada item da rubrica de competências, com o ponto exato do relatório, o código, o teste e a evidência. Status: ✅ demonstrado e executado · ◐ demonstrado, com uma etapa externa ao ambiente de desenvolvimento ainda a registrar.

## Competência 1 — APIs REST com FastAPI aplicando fundamentos de segurança

| # | Item da rubrica | Onde (relatório) | Código / teste | Evidência | |
|---|---|---|---|---|---|
| 1.1 | Ambiente virtual isolado, uvicorn **evidenciando a resposta das rotas**, módulos `routes`/`models`/`database` | Ex. 1 | `main.py`, `routes/`, `models/`, `database/`; `tests/test_ex01_appointments.py` | `evidence/ex01_fundacao/uvicorn_e_rotas.txt` (log do uvicorn + `curl` das rotas), `pip_freeze_venv.txt`, `swagger_docs.png` | ✅ |
| 1.2 | `response_model` controlando exatamente os campos expostos | Ex. 2 | `models/*.py` (`AppointmentPublic`, `AgendaItem`, `PatientPublic`…); `test_ex02::test_nenhum_endpoint_de_consulta_vaza_campos_internos` | `evidence/ex02_templates_xss/sem_vs_com_response_model.txt` | ✅ |
| 1.3 | **Justificar o risco** de exposição quando `response_model` **não** é definido | Ex. 2 (subseção "O risco de não declarar `response_model`") | ataque A9; auditoria OpenAPI O-06 | `sem_vs_com_response_model.txt` (mesmo registro, duas respostas), `resultado_antes.txt` (A9) | ✅ |
| 1.4 | Jinja2 com herança e auto-escape prevenindo XSS | Ex. 2 | `templates/base.html → login/agenda`; `routes/web.py`; `test_ex02::test_pagina_agenda_escapa_conteudo_malicioso_persistido` | `agenda_xss_escapado.png` | ✅ |
| 1.5 | Tríade CIA + frameworks (OWASP, NIST SSDF, MITRE) → controles | Ex. 3 (3.1 e 3.2) | tabelas com arquivo e teste por linha | — | ✅ |
| 1.6 | DFD com trust boundaries e fluxos sensíveis | Ex. 3 (3.3) | `scripts/make_diagrams.py` | `ex03_ex05_diagramas/dfd_nivel1.png` | ✅ |

## Competência 2 — Threat modeling STRIDE e autenticação JWT

| # | Item da rubrica | Onde | Código / teste | Evidência | |
|---|---|---|---|---|---|
| 2.1 | Misuse cases de vetores reais da própria aplicação | Ex. 4 · `docs/ex04_threat_model.md` §3 | MU-01…MU-09, cada um com ataque executável (A1–A10) | `resultado_antes.txt` | ✅ |
| 2.2 | STRIDE + threat model completo (ativos, superfícies, mitigações **rastreáveis**) | Ex. 4 · §1, §2, §4 | `tests/threat_matrix.py` (25 ameaças → 53 verificações) | `docs/matriz_ameaca_teste.md` | ✅ |
| 2.3 | Fronteiras de segurança e vetores nos **3 eixos** de API | Ex. 5 · `docs/ex04_threat_model.md` §7 | diagrama de partições | `ex03_ex05_diagramas/arquitetura_particoes.png` | ✅ |
| 2.4 | `OAuth2PasswordBearer` + bcrypt + rotas com **ownership** | Ex. 6 | `auth/authenticate.py`, `auth/hash_password.py`, `auth/ownership.py`; `test_ex06` | `pytest_ex06.txt` | ✅ |
| 2.5 | JWT com expiração, MFA simulado, **justificar RBAC × ABAC × por recurso** | Ex. 6 (tabela comparativa) | `auth/jwt_handler.py`, `auth/mfa.py`; `test_ex06` (expirado, replay, MFA web) | `pytest_ex06.txt` | ✅ |
| 2.6 | Fluxo OAuth 2.0 adequado + **escopos/claims** humano × M2M | Ex. 7 | `routes/oauth.py`, `auth/rbac.py::require_scopes`; `test_ex07` | `fluxo_client_credentials_curl.txt` | ✅ |

## Competência 3 — Vulnerabilidades OWASP Top 10 e controles defensivos

| # | Item da rubrica | Onde | Código / teste | Evidência | |
|---|---|---|---|---|---|
| 3.1 | Identificar padrões vulneráveis lendo código — **≥ 3 categorias** | Ex. 8 (9 achados, 6 categorias, com arquivo:linha) | `evidence/.../vulnerable_baseline/app.py`; código do Starter Kit | `attack.py` + `resultado_antes.txt` | ✅ |
| 3.2 | Identificar e corrigir **BOLA** com ownership **centralizado** | Ex. 8 e 9 | `auth/ownership.py` (um módulo, usado por todas as rotas por ID); `test_ex09::test_bola_em_todos_os_endpoints_por_id` | `antes_depois.png` (A2–A4) | ✅ |
| 3.3 | Whitelist + regex + `extra='forbid'` | Ex. 9 | `models/base.py` (`StrictModel`, padrões); `test_ex09` | `resultado_depois.txt` (A1, A5) | ✅ |
| 3.4 | Corrigir **XSS stored** com output encoding (auto-escape) | Ex. 2 e 9 | `routes/web.py`; `test_ex02` (grava `<script>` direto no banco) | `agenda_xss_escapado.png`, A7 | ✅ |
| 3.5 | CORS com allowlist, HSTS/X-Frame-Options/X-Content-Type-Options, **rate limit diferenciado** | Ex. 10 | `core/security_headers.py`, `core/rate_limit.py`; `test_ex10` | `headers_cors_curl.txt`, `rate_limit_login_curl.txt` | ✅ |
| 3.6 | SQLModel parametrizado + `BaseSettings`/`.env` sem hardcoding | Ex. 11 | `database/`, `core/config.py`, `.env.example`; `test_ex11` | `pytest_ex11.txt` | ✅ |

## Competência 4 — Pipeline DevSecOps, security gates, ZAP e testes

| # | Item da rubrica | Onde | Código / teste | Evidência | |
|---|---|---|---|---|---|
| 4.1 | **Fase do SDLC** por tipo de ferramenta (estática, dinâmica, dependências, interativa), com justificativa **amarrada ao pipeline** | Ex. 12 (12.1) · `docs/ex12_pipeline_devsecops.md` §2 | `.github/workflows/security-pipeline.yml` | `bandit_antes.txt` | ✅ |
| 4.2 | Priorizar com **CVSS e impacto de negócio** | Ex. 12 (12.3) | `scripts/cvss.py` (validado por teste) | `docs/cvss_priorizacao.md` | ✅ |
| 4.3 | Security gate em **GitHub Actions** com critério definido e justificado pelo aluno, **impedindo merge** | Ex. 12 (12.2 e 12.4) | job `security-gate` + `gate-regression`; `scripts/ci_gate.py`; branch protection descrita | `security-pipeline.yml`, `gate_local_saida.txt` | ◐ *workflow validado e comandos executados localmente; falta o print do check verde após subir o repositório* |
| 4.4 | Estratégia de testes **rastreável ao threat model**, expandindo o teste do Ex. 6 | Ex. 12 (12.5) | `tests/test_ex12_threat_vectors.py`, `tests/threat_matrix.py` | `docs/matriz_ameaca_teste.md` | ✅ |
| 4.5 | **Executar e interpretar scan passivo do ZAP** contra a própria aplicação, correlacionando findings a OWASP e à correção, com **risco residual** e decisão de deploy | Ex. 13 (13.4–13.6) | `scripts/run_zap_passive.sh`, `scripts/zap_report.py`, `core/security_headers.py` (correção do 90004) | `evidence/ex13_capstone/zap/` (4 scans reais, antes e depois da correção), `docs/ex13_zap_correlacao.md`, `docs/ex13_risco_residual.md` | ✅ |
| 4.6 | Testes **unitários com mocking** (teste inicial do Ex. 1 + pontos de entrada e autorização) e **auditoria do OpenAPI** | Ex. 13 (13.2 e 13.3) | `tests/test_ex13_unit_mocks.py` (inclui `TestEx01ComMocks`), `scripts/audit_openapi.py` | `pytest_ex13_unit_mocks_openapi.txt`, `docs/ex13_openapi_audit.md` | ✅ |

## O que a rubrica pede que depende de **você**

* **Vídeo** (até 5 min, YouTube não listado): demonstra 1.1, 3.x e 4.x ao vivo e é a evidência de autoria — roteiro em `docs/ROTEIRO_VIDEO.md`.
* **Item 4.3:** subir o repositório ao GitHub, deixar o workflow rodar, salvar o *print* do check `SECURITY GATE` e ligar o *branch protection* exigindo-o (é isso que "impede o merge").

# Índice de evidências por exercício

Tudo aqui é saída **real**, regenerável com `bash scripts/collect_evidence.sh` (o ZAP, que exige Docker, tem `scripts/run_zap_passive.sh`).

| Ex. | Pasta | O que comprova |
|---|---|---|
| 1 | `ex01_fundacao/` | `pytest_ex01.txt` (teste de consulta), `pip_freeze_venv.txt` (ambiente isolado), `swagger_docs.png` (rotas públicas × protegidas) |
| 2 | `ex02_templates_xss/` | `agenda_normal.png`, `agenda_xss_escapado.png` (payload persistido exibido como texto), `login.png`, HTMLs, `pytest_ex02.txt` |
| 3 e 5 | `ex03_ex05_diagramas/` | `dfd_nivel1.png/.svg` (DFD + trust boundaries + fluxos sensíveis), `arquitetura_particoes.png/.svg` (partições e 3 eixos) |
| 4 | `../docs/ex04_threat_model.md` | misuse cases, STRIDE (5 componentes), DREAD, árvore de ataque, superfícies |
| 6 | `ex06_autenticacao_autorizacao/` | `pytest_ex06.txt` (inclui o teste "não-admin barrado em rota de admin") |
| 7 | `ex07_m2m_escopos/` | `fluxo_client_credentials_curl.txt` (token, claims, 403, `invalid_scope`), `pytest_ex07.txt` |
| 8 e 9 | `ex08_ex09_antes_depois/` | `attack.py` (payloads), `resultado_antes.txt/json` (10/10 explorados), `resultado_depois.txt/json` (0/10), `antes_depois.png`, `vulnerable_baseline/` (**app propositalmente vulnerável — não executar fora de localhost**), `pytest_ex09.txt` |
| 10 | `ex10_hardening/` | `headers_cors_curl.txt`, `rate_limit_login_curl.txt` (5×401 → 429), `pytest_ex10.txt` |
| 11 | `ex11_persistencia/` | `pytest_ex11.txt`; ver também `../.env.example` |
| 12 | `ex12_pipeline/` | `security-pipeline.yml`, `bandit_antes/depois.txt`, `pip_audit_antes/depois.txt` (+`.json`), `starter_kit_requirements.txt`, `gate_local_saida.txt`, `pytest_ex12.txt`; tabela CVSS em `../docs/cvss_priorizacao.md` |
| 1 | `ex01_fundacao/uvicorn_e_rotas.txt` | log do uvicorn subindo + `curl` das rotas (rubrica 1.1) |
| 2 | `ex02_templates_xss/sem_vs_com_response_model.txt` | mesmo registro **sem** e **com** `response_model` (rubrica 1.3) |
| 13 | `ex13_capstone/` | `pytest_suite_completa_com_cobertura.txt` (197 passed, 96 %), `pytest_ex13_unit_mocks_openapi.txt`, `e2e_demo.txt`, `openapi.json`, **`zap/` (4 scans reais do ZAP + antes/depois da correção do achado 90004)**; auditoria em `../docs/ex13_openapi_audit.md`; risco residual em `../docs/ex13_risco_residual.md` |

> `evidence/.local/` (credenciais de demonstração, segredo do laboratório, logs, bancos locais) **não** entra no ZIP.

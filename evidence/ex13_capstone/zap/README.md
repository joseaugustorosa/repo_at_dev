# Saída do OWASP ZAP (scan passivo) — execução real

Gerada por `bash scripts/run_zap_passive.sh` (ZAP 2.17.0, imagem oficial, Docker/Colima) contra a API local com
`COOKIE_SECURE=true`. **Todos os scans são passivos** (`zap-baseline.py` e `zap-api-scan.py -S`); a prova está em
`prova_scan_passivo_log_de_acesso.txt` (a API recebeu ~60 requisições, nenhuma com payload de ataque).

| Arquivo | Conteúdo |
|---|---|
| `baseline_report.{html,json,md}` / `log_baseline.txt` | spider + passivo a partir de `/` (3 URLs) |
| `baseline_web_report.*` / `log_baseline_web.txt` | spider + passivo a partir de `/web/login` (página HTML) |
| `api_recepcao_report.*` / `log_api_recepcao.txt` | importa o OpenAPI (27 URLs), autenticado como **recepcionista** |
| `api_helena_report.*` / `log_api_helena.txt` | idem, autenticado como **profissional** |
| `execucao_1_antes_da_correcao/` | **1ª execução**: continha o achado `90004` (COEP ausente, Baixo) |
| `rules.tsv` | regras usadas (cópia de `.zap/rules.tsv`) |
| `../../docs/ex13_zap_correlacao.md` | alerta → CWE → OWASP → controle → teste → status (gerado por `zap_report.py`) |

Reproduzir: suba a API (`COOKIE_SECURE=true uvicorn main:app --no-server-header`), tenha Docker ativo e rode
`bash scripts/run_zap_passive.sh`. No GitHub Actions o job `dast-passive` faz o equivalente.

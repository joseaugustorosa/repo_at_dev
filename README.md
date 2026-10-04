# API de Agendamento Clínico — Assessment DR2 (Desenvolvimento Seguro de Aplicações Web)

FastAPI + SQLModel para pacientes, profissionais e consultas, com autenticação JWT/bcrypt/MFA, autorização RBAC + ownership,
integração M2M (Client Credentials com escopos), página HTML segura para a recepção e pipeline DevSecOps.
**Relatório técnico:** [`RELATORIO_TECNICO.md`](RELATORIO_TECNICO.md) (e `.pdf`). **Vídeo (YouTube, não listado):** `https://youtu.be/<COLOQUE-O-LINK-AQUI>`
**Repositório (GitHub):** <https://github.com/joseaugustorosa/repo_at_dev> · **Pasta da entrega (Google Drive):** <https://drive.google.com/drive/folders/1Rd5TseE5pK02Be37Nml3IpVy_p2W_FUy?usp=sharing>

## Como rodar

Testado em **Python 3.13** (macOS). Requer `bcrypt`/`cryptography` wheels disponíveis para a sua plataforma.

```bash
python3.13 -m venv .venv && source .venv/bin/activate        # ambiente isolado
pip install -r requirements-dev.txt

python scripts/bootstrap_env.py                              # cria .env LOCAL com segredos aleatórios (nunca versione)
python scripts/seed_demo.py                                  # dados fictícios + credenciais em evidence/.local/
uvicorn main:app --no-server-header                          # http://127.0.0.1:8000/docs
```

* Primeiro administrador "de verdade": `python scripts/create_admin.py "Nome Sobrenome" admin@clinica.com.br` (senha pedida no terminal; imprime o URI TOTP).
* Admin faz login em 2 passos: `POST /user/signin` → `mfa_token`; `POST /user/mfa/verify` com o código do app autenticador.
* Laboratório: `POST /oauth/token` (`grant_type=client_credentials`, escopo `availability:read`); segredo gravado em `evidence/.local/lab_client_secret.txt`.
* Página da recepção: `http://127.0.0.1:8000/web/login` (usuário `recepcao@demo.clinica.com.br`; senha em `evidence/.local/demo_credentials.json`).

## Testes, gates e evidências

```bash
python -m pytest                                  # 197 testes (um arquivo por exercício) — cobertura: --cov
bash scripts/security_gate_local.sh               # mesmos gates do CI: testes+cobertura, Bandit (>= MEDIUM), pip-audit
python scripts/audit_openapi.py                   # auditoria do contrato OpenAPI (12 checks)
python scripts/e2e_demo.py                        # demonstração ponta a ponta contra a API em execução
bash scripts/collect_evidence.sh                  # regenera as evidências em evidence/ (usa Chrome headless p/ prints)
bash scripts/run_zap_passive.sh                   # scan passivo do OWASP ZAP via Docker (app em :8000 com COOKIE_SECURE=true)
python scripts/build_report.py                    # reconstrói RELATORIO_TECNICO.pdf
```

Antes/depois do Exercício 9 (executa os mesmos 10 ataques nas duas versões):
`evidence/ex08_ex09_antes_depois/` → `attack.py`, `resultado_antes.txt` (10/10 explorados), `resultado_depois.txt` (0/10).

## Estrutura

`routes/` (APIRouter por recurso) · `models/` (SQLModel + Pydantic) · `database/` · `auth/` (camada separada: JWT, MFA, middleware, RBAC, ownership) ·
`core/` (BaseSettings, headers, rate limit, auditoria, CSRF) · `templates/` · `tests/` · `scripts/` · `.github/workflows/` · `docs/` · `evidence/`.

## Segurança do pacote

* **Nenhum segredo real**: só `.env.example` (placeholders). `.env`, bancos, `evidence/.local/` e `.venv/` ficam fora do ZIP (`scripts/make_zip.sh` verifica).
* `evidence/ex08_ex09_antes_depois/vulnerable_baseline/` é **propositalmente vulnerável** (demonstração do "antes"); nunca execute fora de localhost.
* `tests/fixtures/zap_sample_report.json` é uma *fixture sintética* para testar o conversor do ZAP — **não** é saída de scan real.

## Checklist de entrega (o que ainda é com você)

- [ ] Gravar o **vídeo de até 5 min** (roteiro em [`docs/ROTEIRO_VIDEO.md`](docs/ROTEIRO_VIDEO.md)), publicar no YouTube como **não listado** e colocar o link em `RELATORIO_TECNICO.md` e neste README (busque por `COLOQUE-O-LINK-AQUI`).
- [x] Repositório no GitHub e workflow executado: run verde (`evidence/ex12_pipeline/actions_run_verde.txt`).
- [ ] **Ligar o branch protection** na `main` exigindo o check `SECURITY GATE` (*Settings → Branches*) e salvar um print do check verde / da regra em `evidence/ex12_pipeline/`. O ZAP já foi executado localmente e no Actions.
- [ ] Conferir o **nome completo** no relatório e rodar `bash scripts/make_zip.sh` (gera `jose_nascimento_DR2_AT.zip`; ajuste o nome se necessário).
- [ ] Reconstruir o PDF do relatório (`python scripts/build_report.py`) depois de editar.

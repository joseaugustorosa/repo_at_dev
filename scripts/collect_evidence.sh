#!/usr/bin/env bash
# Regenera TODAS as evidências em evidence/ de forma reproduzível (usa saídas reais; nada é digitado à mão).
# Pré-requisitos: .venv ativo com requirements-dev.txt; Google Chrome (capturas de tela, opcional).
# Uso: bash scripts/collect_evidence.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PY=python
E=evidence
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BASE=http://127.0.0.1:8000
mkdir -p $E/.local

[ -f .env ] || $PY scripts/bootstrap_env.py
[ -f $E/.local/demo_credentials.json ] || { rm -f clinica.db; $PY scripts/seed_demo.py; }

start_fixed()  { pkill -f "uvicorn main:app" 2>/dev/null; sleep 1; nohup uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header > $E/.local/server.log 2>&1 & sleep 3; }
start_base()   { pkill -f "uvicorn app:app" 2>/dev/null; sleep 1; rm -f $E/.local/baseline.db
                 (cd $E/ex08_ex09_antes_depois/vulnerable_baseline && nohup uvicorn app:app --host 127.0.0.1 --port 8001 > ../../.local/baseline.log 2>&1 &); sleep 3; }
stop_all()     { pkill -f "uvicorn main:app" 2>/dev/null; pkill -f "uvicorn app:app" 2>/dev/null; }
shot()         { [ -x "$CHROME" ] && "$CHROME" --headless=new --disable-gpu --hide-scrollbars --window-size="$2" --virtual-time-budget=10000 --screenshot="$PWD/$3" "$1" >/dev/null 2>&1; }

echo "== 1/7 testes por exercício"
ex() { out=$1; shift; $PY -m pytest -v --no-header -p no:cacheprovider "$@" 2>&1 | sed 's/ \[ *[0-9]*%\]//' > "$out"; echo "   $(tail -1 "$out")  <- $out"; }
ex $E/ex01_fundacao/pytest_ex01.txt tests/test_ex01_appointments.py
ex $E/ex02_templates_xss/pytest_ex02.txt tests/test_ex02_response_models_xss.py
ex $E/ex06_autenticacao_autorizacao/pytest_ex06.txt tests/test_ex06_authz.py
ex $E/ex07_m2m_escopos/pytest_ex07.txt tests/test_ex07_m2m_scopes.py
ex $E/ex08_ex09_antes_depois/pytest_ex09.txt tests/test_ex09_input_validation.py
ex $E/ex10_hardening/pytest_ex10.txt tests/test_ex10_hardening.py
ex $E/ex11_persistencia/pytest_ex11.txt tests/test_ex11_persistence.py
ex $E/ex12_pipeline/pytest_ex12.txt tests/test_ex12_threat_vectors.py tests/test_ex12_ci_gate.py tests/test_cvss_calculator.py tests/test_zap_report.py
ex $E/ex13_capstone/pytest_ex13_unit_mocks_openapi.txt tests/test_ex13_unit_mocks.py tests/test_ex13_openapi_audit.py
$PY -m pytest -v --no-header -p no:cacheprovider --cov --cov-report=term-missing 2>&1 | sed 's/ \[ *[0-9]*%\]//' > $E/ex13_capstone/pytest_suite_completa_com_cobertura.txt
echo "   suite completa: $(grep -E '^=+ .* passed|failed' $E/ex13_capstone/pytest_suite_completa_com_cobertura.txt | tail -1)"
$PY -m pip list --format=freeze > $E/ex01_fundacao/pip_freeze_venv.txt

echo "== 2/7 antes x depois (Ex. 8/9)"
start_base; start_fixed
# antes dos ataques (que alteram dados e esgotam o rate limit): mesma consulta, sem x com response_model
$PY scripts/compare_response_model.py > $E/ex02_templates_xss/sem_vs_com_response_model.txt 2>&1
( cd $E/ex08_ex09_antes_depois
  $PY attack.py --target baseline --json resultado_antes.json  > resultado_antes.txt  2>&1
  $PY attack.py --target fixed    --json resultado_depois.json > resultado_depois.txt 2>&1
  tail -1 resultado_antes.txt resultado_depois.txt )
$PY scripts/make_before_after.py
shot "file://$PWD/$E/ex08_ex09_antes_depois/antes_depois.html" 1250,640 $E/ex08_ex09_antes_depois/antes_depois.png
stop_all

echo "== 3/7 cabeçalhos, CORS, rate limit, M2M, demo ponta a ponta (servidor reiniciado entre blocos p/ zerar contadores)"
start_fixed
{ echo "\$ curl -i $BASE/health"; curl -s -i $BASE/health
  echo; echo "\$ curl -i -H 'Origin: https://evil.example.org' $BASE/health   # origem NÃO permitida"
  curl -s -i -H 'Origin: https://evil.example.org' $BASE/health | grep -i -E "^HTTP|access-control|vary"; echo "(sem Access-Control-Allow-Origin => o navegador bloqueia a leitura)"
  echo; echo "\$ curl -i -H 'Origin: http://localhost:3000' $BASE/health      # origem da allowlist"
  curl -s -i -H 'Origin: http://localhost:3000' $BASE/health | grep -i -E "^HTTP|access-control|vary"
  echo; echo "\$ preflight OPTIONS de origem maliciosa"
  curl -s -i -X OPTIONS -H 'Origin: https://evil.example.org' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: authorization' $BASE/appointment/new | head -4
  echo; echo "\$ preflight OPTIONS de origem permitida"
  curl -s -i -X OPTIONS -H 'Origin: http://localhost:3000' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: authorization,content-type' $BASE/appointment/new | grep -i -E "^HTTP|access-control"
} > $E/ex10_hardening/headers_cors_curl.txt 2>&1
start_fixed
{ echo "# Rate limit do login: 5 tentativas/min por (conta+IP); a 6ª recebe 429 + Retry-After"
  for i in 1 2 3 4 5 6 7; do printf "tentativa %s -> " $i; curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST $BASE/user/signin -d "username=alvo@clinica.com.br&password=senha-errada-$i"; done
  echo; echo "# Cabeçalho Retry-After:"; curl -s -i -X POST $BASE/user/signin -d "username=alvo@clinica.com.br&password=x" | grep -i -E "^HTTP|retry-after|^\{"
} > $E/ex10_hardening/rate_limit_login_curl.txt 2>&1
start_fixed
$PY scripts/e2e_demo.py > $E/ex13_capstone/e2e_demo.txt 2>&1
start_fixed
LAB_SECRET=$(cat $E/.local/lab_client_secret.txt)
{ echo "# Ex.7 — Client Credentials (laboratório parceiro)"
  echo; echo "\$ curl -X POST /oauth/token -d grant_type=client_credentials -d client_id=laboratorio-parceiro -d client_secret=<redigido> -d scope=availability:read"
  RESP=$(curl -s -X POST $BASE/oauth/token -d grant_type=client_credentials -d client_id=laboratorio-parceiro --data-urlencode "client_secret=$LAB_SECRET" -d scope=availability:read)
  echo "$RESP" | $PY -c "import sys,json; d=json.load(sys.stdin); t=d['access_token']; d['access_token']=t[:25]+'...(redigido)'; print(json.dumps(d,indent=2))"
  TOKEN=$(echo "$RESP" | $PY -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  echo; echo "# Claims do token do laboratório (sem 'role'; com 'scope' e token_use=m2m)"
  $PY - "$TOKEN" <<'PYEOF'
import base64, json, sys
p = sys.argv[1].split(".")[1]; p += "=" * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
PYEOF
  echo; echo "# Mesmo token em rotas de usuários => 403"
  for route in /patient/ /appointment/ /user/; do printf "GET %-14s -> " $route; curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Authorization: Bearer $TOKEN" $BASE$route; done
  echo; echo "# Escopo fora do contrato => invalid_scope"
  curl -s -X POST $BASE/oauth/token -d grant_type=client_credentials -d client_id=laboratorio-parceiro --data-urlencode "client_secret=$LAB_SECRET" -d scope="availability:read patients:read"; echo
  echo; echo "# Segredo errado => invalid_client (401)"
  curl -s -i -X POST $BASE/oauth/token -d grant_type=client_credentials -d client_id=laboratorio-parceiro -d client_secret=segredo-errado | grep -E "^HTTP|^\{"
} > $E/ex07_m2m_escopos/fluxo_client_credentials_curl.txt 2>&1

echo "== 4/7 capturas de tela e uvicorn (Ex. 1)"
pkill -f "uvicorn main:app" 2>/dev/null; sleep 1
: > $E/.local/ex01_uvicorn.log
( uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header > $E/.local/ex01_uvicorn.log 2>&1 & ); sleep 3
TOK=$($PY scripts/demo_token.py helena@demo.clinica.com.br)
{ echo "\$ source .venv/bin/activate && uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header"
  head -6 $E/.local/ex01_uvicorn.log
  echo; echo "\$ curl -i $BASE/                       # rota pública"; curl -s -i $BASE/ | sed -n '1p;$p'
  echo; echo "\$ curl -i $BASE/health                 # rota pública"; curl -s -i $BASE/health | sed -n '1p;$p'
  echo; echo "\$ curl -i $BASE/appointment/           # sem token => deny-by-default"; curl -s -i $BASE/appointment/ | grep -E "^HTTP|www-authenticate|^\{"
  echo; echo "\$ curl -H 'Authorization: Bearer <token>' $BASE/appointment/   # profissional autenticado"
  curl -s -H "Authorization: Bearer $TOK" $BASE/appointment/ | $PY -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d[:1], indent=2, ensure_ascii=False)); print('... total:', len(d), 'consulta(s) — só as do próprio profissional')"
  echo; echo "\$ curl -s $BASE/openapi.json | jq '.paths | keys'"; curl -s $BASE/openapi.json | $PY -c "import sys,json; print(json.dumps(sorted(json.load(sys.stdin)['paths']), indent=2))"
  echo; echo "# estrutura modular:"; ls -d routes models database auth core | sed 's/^/  /'
} > $E/ex01_fundacao/uvicorn_e_rotas.txt 2>&1
stop_all
start_fixed
shot "$BASE/docs" 1200,1500 $E/ex01_fundacao/swagger_docs.png
stop_all
$PY scripts/make_screenshots.py
for n in login agenda_normal agenda_xss_escapado; do shot "file://$PWD/$E/ex02_templates_xss/$n.html" 1100,520 $E/ex02_templates_xss/$n.png; done
$PY scripts/make_diagrams.py
shot "file://$PWD/$E/ex03_ex05_diagramas/dfd_nivel1.svg" 1300,830 $E/ex03_ex05_diagramas/dfd_nivel1.png
shot "file://$PWD/$E/ex03_ex05_diagramas/arquitetura_particoes.svg" 1240,860 $E/ex03_ex05_diagramas/arquitetura_particoes.png

echo "== 5/7 SAST / SCA (Ex. 12)"
B=$E/ex08_ex09_antes_depois/vulnerable_baseline
{ echo "### Bandit na versão VULNERÁVEL — comparação de critérios de bloqueio"
  echo; echo "--- (a) critério do exemplo da aula: -lll (somente HIGH)"
  bandit -r $B -lll -q >/dev/null 2>&1; echo "exit code: $?   (0 = pipeline passaria; a SQL injection NÃO seria bloqueada)"
  echo; echo "--- (b) critério adotado: -ll (MEDIUM ou maior)"
  bandit -r $B -ll -q 2>&1 | grep -E "Issue:|Severity|Location"; bandit -r $B -ll -q >/dev/null 2>&1; echo "exit code: $?   (1 = pipeline bloqueado)"
  echo; echo "--- (c) tudo que o Bandit enxerga (todas as severidades) — o que fica fora do gate"
  bandit -r $B -q -f custom --msg-template "{severity:<6} {test_id} {relpath}:{line}  {msg}" 2>&1 | grep -v "^\[main\]"
} > $E/ex12_pipeline/bandit_antes.txt
{ echo "### Bandit na versão FINAL (gate: -ll)"; bandit -r auth core database models routes main.py scripts -ll 2>&1 | grep -v "^\[main\]" | tail -22
  bandit -r auth core database models routes main.py scripts -ll -q >/dev/null 2>&1; echo "exit code: $?"
} > $E/ex12_pipeline/bandit_depois.txt
{ echo "### SCA (pip-audit) — dependências FIXADAS no Starter Kit da disciplina"
  pip-audit --no-deps --disable-pip -r $E/ex12_pipeline/starter_kit_requirements.txt --progress-spinner off 2>&1 | grep -v "^WARNING"
} > $E/ex12_pipeline/pip_audit_antes.txt
{ echo "### SCA (pip-audit) — dependências da versão FINAL (requirements.txt), incluindo transitivas"
  pip-audit -r requirements.txt --strict 2>&1; echo "exit code: $?"
} > $E/ex12_pipeline/pip_audit_depois.txt
cp .github/workflows/security-pipeline.yml $E/ex12_pipeline/security-pipeline.yml
bash scripts/security_gate_local.sh > $E/ex12_pipeline/gate_local_saida.txt 2>&1; tail -3 $E/ex12_pipeline/gate_local_saida.txt

echo "== 6/7 documentos gerados (CVSS, OpenAPI, matriz ameaça→teste)"
$PY scripts/cvss.py --write
$PY scripts/audit_openapi.py --write > /dev/null; echo "   OpenAPI audit exit=$?"
$PY scripts/gen_traceability.py

echo "== 7/7 pronto. O ZAP (Docker) é separado: COOKIE_SECURE=true uvicorn main:app ... & bash scripts/run_zap_passive.sh"

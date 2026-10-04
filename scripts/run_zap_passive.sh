#!/usr/bin/env bash
# Scan PASSIVO do OWASP ZAP contra a API local, via Docker (alternativa/complemento ao GitHub Actions).
# Pré-requisitos: Docker em execução; app no ar em :8000 (uvicorn main:app --no-server-header);
#                 python scripts/bootstrap_env.py && python scripts/seed_demo.py   (contas de demonstração)
# Saída em evidence/ex13_capstone/zap/:
#   baseline_report.*          spider + regras passivas a partir de "/" (a raiz devolve JSON: o spider só enxerga 3 URLs)
#   baseline_web_report.*      spider + regras passivas a partir de /web/login (página HTML: formulário, CSRF, cookies)
#   api_recepcao_report.*      importa o openapi.json e visita TODAS as rotas autenticado como RECEPCIONISTA
#   api_helena_report.*        idem, autenticado como PROFISSIONAL (para varrer o conteúdo das rotas de consultas/pacientes)
#   log_*.txt                  console do ZAP (lista de regras PASS/WARN/FAIL)
#   Usa `-S` (safe mode do zap-api-scan): NÃO executa ataque ativo — só observa as respostas.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$PWD/evidence/ex13_capstone/zap"; mkdir -p "$OUT"
IMAGE="ghcr.io/zaproxy/zaproxy:stable"
# Em Docker Desktop/Colima o contêiner alcança o host por host.docker.internal.
TARGET="${TARGET:-http://host.docker.internal:8000}"
cp .zap/rules.tsv "$OUT/rules.tsv"      # vai no mesmo volume (evita montar arquivo sobre diretório)

replacer() {  # injeta o cabeçalho Authorization em toda requisição do ZAP
  echo "-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization \
-config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=Bearer\\ $1"
}

echo "== ZAP baseline (spider + passivo) a partir de /"
docker run --rm -v "$OUT:/zap/wrk:rw" "$IMAGE" zap-baseline.py -t "$TARGET" -c rules.tsv \
  -J baseline_report.json -r baseline_report.html -w baseline_report.md > "$OUT/log_baseline.txt" 2>&1 || true

echo "== ZAP baseline (spider + passivo) a partir de /web/login (página HTML)"
docker run --rm -v "$OUT:/zap/wrk:rw" "$IMAGE" zap-baseline.py -t "$TARGET/web/login" -c rules.tsv \
  -J baseline_web_report.json -r baseline_web_report.html -w baseline_web_report.md > "$OUT/log_baseline_web.txt" 2>&1 || true

for who in recepcao helena; do
  echo "== ZAP API scan (-S, passivo) autenticado como $who"
  TOKEN="$(python scripts/demo_token.py "$who@demo.clinica.com.br")"
  docker run --rm -v "$OUT:/zap/wrk:rw" "$IMAGE" zap-api-scan.py -t "$TARGET/openapi.json" -f openapi -S -c rules.tsv \
    -J "api_${who}_report.json" -r "api_${who}_report.html" -w "api_${who}_report.md" \
    -z "$(replacer "$TOKEN")" > "$OUT/log_api_${who}.txt" 2>&1 || true
done

echo "== gate + correlação"
REPORTS="$OUT/baseline_report.json,$OUT/baseline_web_report.json,$OUT/api_recepcao_report.json,$OUT/api_helena_report.json"
LOGS="$OUT/log_baseline.txt,$OUT/log_baseline_web.txt,$OUT/log_api_recepcao.txt,$OUT/log_api_helena.txt"
python scripts/zap_report.py gate "$REPORTS"
python scripts/zap_report.py report "$REPORTS" docs/ex13_zap_correlacao.md --logs "$LOGS"

# Prova de que o scan foi PASSIVO: o log de acesso da aplicação não pode ter payload de ataque (opcional)
APP_LOG="${APP_LOG:-evidence/.local/zap_app.log}"
if [ -f "$APP_LOG" ]; then
  { echo "# Requisições que a API recebeu durante os scans do ZAP (log de acesso do uvicorn)"
    echo "total: $(grep -c 'HTTP/1.1"' "$APP_LOG")"
    echo "com payload típico de ataque ativo (SQLi/XSS/traversal/time-based): $(grep -c -i -E 'union%20select|%27%20or|<script|alert\(|%3Cscript|\.\./|etc/passwd|sleep\(|waitfor|OR%201%3D1|%2527' "$APP_LOG" || true)"
    echo; echo "por método/status:"; grep 'HTTP/1.1"' "$APP_LOG" | awk '{print $6, $9}' | tr -d '"' | sort | uniq -c | sort -rn
  } > "$OUT/prova_scan_passivo_log_de_acesso.txt"
fi

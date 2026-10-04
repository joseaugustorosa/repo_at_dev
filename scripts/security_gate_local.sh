#!/usr/bin/env bash
# Executa localmente os MESMOS gates do pipeline (.github/workflows/security-pipeline.yml).
# Uso: bash scripts/security_gate_local.sh      (saída 0 = liberado; != 0 = bloqueado)
set -uo pipefail
cd "$(dirname "$0")/.."
status=0
run() { echo; echo "=== $1"; shift; "$@"; code=$?; echo "-> exit code: $code"; [ $code -eq 0 ] || status=1; }

run "Testes de segurança + cobertura mínima (pytest)" python -m pytest -q --cov=. --cov-report=term-missing:skip-covered --cov-fail-under=85
run "SAST — Bandit (bloqueia severidade MEDIUM ou maior)" bandit -r auth core database models routes main.py scripts -ll -q
run "SCA — pip-audit (bloqueia qualquer CVE conhecida nas dependências diretas e transitivas)" pip-audit -r requirements.txt --strict
echo; [ $status -eq 0 ] && echo "SECURITY GATE: LIBERADO" || echo "SECURITY GATE: BLOQUEADO"
exit $status

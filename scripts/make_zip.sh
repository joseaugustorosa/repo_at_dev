#!/usr/bin/env bash
# Empacota a entrega em ../<nome>.zip, SEM segredos, e verifica vazamentos antes de zipar.
# Uso: bash scripts/make_zip.sh [nome_sobrenome_DR2_AT]     (padrão: jose_nascimento_DR2_AT)
set -euo pipefail
cd "$(dirname "$0")/.."
NAME="${1:-jose_nascimento_DR2_AT}"
STAGE="$PWD/.build/zipstage/$NAME"
OUT="$(cd .. && pwd)/${NAME}.zip"

echo "== reconstruindo o PDF do relatório"
python scripts/build_report.py

echo "== montando pacote (sem .venv, .env, bancos, caches, evidence/.local)"
rm -rf "$PWD/.build/zipstage"; mkdir -p "$STAGE"
rsync -a --exclude-from=- ./ "$STAGE/" <<'EXCLUDES'
.venv/
.env
*.db
*.sqlite3
__pycache__/
*.pyc
.pytest_cache/
.coverage
htmlcov/
.build/
evidence/.local/
.DS_Store
node_modules/
EXCLUDES

echo "== verificações de vazamento"
python - "$STAGE" <<'PY'
import json, re, sys
from pathlib import Path

stage = Path(sys.argv[1])
root = stage.parent.parent.parent  # projeto
fail = []
if (stage / ".env").exists():
    fail.append(".env real dentro do pacote")
if not (stage / ".env.example").exists():
    fail.append(".env.example ausente")

# valores secretos LOCAIS que jamais podem aparecer em qualquer arquivo do pacote
secrets = set()
env = root / ".env"
if env.exists():
    for line in env.read_text().splitlines():
        k, _, v = line.partition("=")
        if k in {"JWT_SECRET_KEY", "MFA_MASTER_KEY", "LAB_CLIENT_SECRET_HASH"} and len(v) > 12:
            secrets.add(v.strip())
local = root / "evidence" / ".local"
if (local / "lab_client_secret.txt").exists():
    secrets.add((local / "lab_client_secret.txt").read_text().strip())
if (local / "demo_credentials.json").exists():
    for info in json.loads((local / "demo_credentials.json").read_text()).values():
        secrets.add(info["password"])
        if info.get("mfa_uri"):
            m = re.search(r"secret=([A-Z2-7]+)", info["mfa_uri"])
            if m:
                secrets.add(m.group(1))

jwt_like = re.compile(r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}")
pem = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
for f in stage.rglob("*"):
    if not f.is_file() or f.suffix in {".png", ".pdf", ".ico"}:
        continue
    try:
        text = f.read_text()
    except UnicodeDecodeError:
        continue
    rel = f.relative_to(stage)
    for s in secrets:
        if s and s in text:
            fail.append(f"segredo local encontrado em {rel}")
    if jwt_like.search(text):
        fail.append(f"JWT completo em {rel}")
    if pem.search(text):
        fail.append(f"chave privada em {rel}")
if fail:
    print("FALHA:\n  " + "\n  ".join(sorted(set(fail))))
    sys.exit(1)
print(f"ok: {len(secrets)} segredos locais verificados; nenhum vazamento, nenhum .env, nenhum JWT completo")
PY

echo "== zip"
rm -f "$OUT"
( cd "$PWD/.build/zipstage" && zip -r -X -q "$OUT" "$NAME" )
unzip -tq "$OUT"
echo "gerado: $OUT ($(du -h "$OUT" | cut -f1)), $(unzip -Z1 "$OUT" | wc -l | tr -d ' ') entradas"

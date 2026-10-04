"""Imprime um access token de uma conta de DEMONSTRAÇÃO (para o ZAP varrer rotas autenticadas).

Uso: python scripts/demo_token.py recepcao@demo.clinica.com.br [http://127.0.0.1:8000]
Lê a senha em evidence/.local/demo_credentials.json (gerado por seed_demo.py; fora do git/ZIP).
Só usar contas não-admin: o token do ZAP não deve ter MFA nem privilégios administrativos.
"""
import json
import sys
from pathlib import Path

import httpx2 as httpx

email = sys.argv[1]
base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8000"
creds = json.loads((Path(__file__).resolve().parent.parent / "evidence" / ".local" / "demo_credentials.json").read_text())
if creds[email]["role"] == "admin":
    sys.exit("recuse: não gere token de admin para ferramentas de scan")
r = httpx.post(f"{base}/user/signin", data={"username": email, "password": creds[email]["password"]}, timeout=10)
r.raise_for_status()
print(r.json()["access_token"])

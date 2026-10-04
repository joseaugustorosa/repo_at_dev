"""Imprime um access token de uma conta de DEMONSTRAÇÃO (para o ZAP varrer rotas autenticadas).

Uso: python scripts/demo_token.py recepcao@demo.clinica.com.br [http://127.0.0.1:8000]
Lê a senha em evidence/.local/demo_credentials.json (gerado por seed_demo.py; fora do git/ZIP).
Só usa a biblioteca padrão: roda no CI sem instalar nada além de requirements.txt.
Só usar contas não-admin: o token do ZAP não deve ter MFA nem privilégios administrativos.
"""
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

email = sys.argv[1]
base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8000"
if urllib.parse.urlparse(base).scheme not in {"http", "https"}:  # impede file:// e esquemas customizados
    sys.exit("URL base deve ser http(s)")
creds = json.loads((Path(__file__).resolve().parent.parent / "evidence" / ".local" / "demo_credentials.json").read_text())
if creds[email]["role"] == "admin":
    sys.exit("recuse: não gere token de admin para ferramentas de scan")
data = urllib.parse.urlencode({"username": email, "password": creds[email]["password"]}).encode()
request = urllib.request.Request(f"{base}/user/signin", data=data, method="POST")
# esquema validado acima (somente http/https) -> B310 não se aplica
with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310
    print(json.load(response)["access_token"])

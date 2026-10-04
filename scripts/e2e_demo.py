"""Demonstração ponta a ponta contra a API em execução (vídeo + evidência do Ex. 13).

Pré-requisitos:  python scripts/bootstrap_env.py && python scripts/seed_demo.py
                 uvicorn main:app --no-server-header
Uso:             python scripts/e2e_demo.py [http://127.0.0.1:8000]
"""
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

import httpx2 as httpx
import pyotp

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "evidence" / ".local"
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
creds = json.loads((LOCAL / "demo_credentials.json").read_text())
lab_secret = (LOCAL / "lab_client_secret.txt").read_text().strip()
http = httpx.Client(base_url=BASE, timeout=10)


def step(title: str) -> None:
    print(f"\n=== {title}")


def redact(text: str) -> str:
    """Nenhum token (mesmo expirado) vai para as evidências."""
    return re.sub(r"eyJ[\w-]+(\.[\w-]*)*", "eyJ…(token redigido)", text)


def show(r: httpx.Response, keys: tuple[str, ...] = ()) -> None:
    body = redact(r.text) if len(r.text) < 300 else redact(r.text)[:300] + "…"
    print(f"  -> HTTP {r.status_code} {body}")
    for k in keys:
        print(f"     {k}: {r.headers.get(k)}")


def login(email: str) -> str:
    r = http.post("/user/signin", data={"username": email, "password": creds[email]["password"]})
    return r.json()["access_token"]


def bearer(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


step("1. Sem token: tudo é negado (deny-by-default)")
show(http.get("/appointment/"), ("www-authenticate",))

step("2. Profissional (Dra. Helena) lista as PRÓPRIAS consultas — sem campos internos")
helena = login("helena@demo.clinica.com.br")
r = http.get("/appointment/", headers=bearer(helena))
show(r)
mine = r.json()

step("3. BOLA: Dr. Paulo tenta ler a consulta da Dra. Helena trocando o ID na URL")
paulo = login("paulo@demo.clinica.com.br")
show(http.get(f"/appointment/{mine[0]['id']}", headers=bearer(paulo)))
print("     (404 igual ao de 'inexistente': não confirma que o ID existe)")

step("4. Mass assignment: tentar escolher 'professional_id' no corpo")
patient_id = mine[0]["patient_id"]
when = (date.today() + timedelta(days=9)).isoformat() + "T15:00:00"
show(http.post("/appointment/new", headers=bearer(helena),
               json={"patient_id": patient_id, "date_time": when, "reason": "Teste", "professional_id": 99}))

step("5. Stored XSS: motivo com <script> é rejeitado na entrada")
show(http.post("/appointment/new", headers=bearer(helena),
               json={"patient_id": patient_id, "date_time": when, "reason": "<script>alert(1)</script>"}))

step("6. Recepção NÃO cria consulta, mas vê a agenda sem dados clínicos")
recep = login("recepcao@demo.clinica.com.br")
show(http.post("/appointment/new", headers=bearer(recep),
               json={"patient_id": patient_id, "date_time": when, "reason": "Teste"}))
show(http.get("/appointment/agenda", headers=bearer(recep),
              params={"day": mine[0]["date_time"][:10]}))

step("7. Não-admin em rota de admin => 403; admin exige MFA (TOTP)")
show(http.get("/user/", headers=bearer(recep)))
admin_email = "admin@demo.clinica.com.br"
challenge = http.post("/user/signin", data={"username": admin_email, "password": creds[admin_email]["password"]})
show(challenge)
totp = pyotp.parse_uri(creds[admin_email]["mfa_uri"])
r = http.post("/user/mfa/verify", json={"mfa_token": challenge.json()["mfa_token"], "code": totp.now()})
show(r)
admin_token = r.json()["access_token"]
show(http.get("/user/", headers=bearer(admin_token)))

step("8. Laboratório (M2M): Client Credentials com escopo availability:read")
r = http.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": "laboratorio-parceiro",
                                    "client_secret": lab_secret, "scope": "availability:read"})
show(r)
lab = r.json()["access_token"]
day = mine[0]["date_time"][:10]
show(http.get("/availability/", headers=bearer(lab),
              params={"professional_id": mine[0]["professional_id"], "day": day}))
print("  Mesmo token do laboratório em rotas de usuários:")
show(http.get("/patient/", headers=bearer(lab)), ("www-authenticate",))
print("  Pedir escopo que o contrato não prevê:")
show(http.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": "laboratorio-parceiro",
                                     "client_secret": lab_secret, "scope": "patients:read"}))

step("9. Cabeçalhos de segurança e CORS (allowlist)")
r = http.get("/health", headers={"Origin": "https://evil.example.org"})
print("  Origin maliciosa -> access-control-allow-origin:", r.headers.get("access-control-allow-origin"))
r = http.get("/health", headers={"Origin": "http://localhost:3000"})
print("  Origin permitida -> access-control-allow-origin:", r.headers.get("access-control-allow-origin"))
show(r, ("strict-transport-security", "x-frame-options", "x-content-type-options"))

step("10. Rate limit do login: 5 tentativas/min (a 6ª recebe 429)")
for i in range(1, 7):
    r = http.post("/user/signin", data={"username": "alvo@clinica.com.br", "password": f"tentativa-{i}-x"})
    print(f"  tentativa {i}: HTTP {r.status_code}", r.headers.get("retry-after") or "")

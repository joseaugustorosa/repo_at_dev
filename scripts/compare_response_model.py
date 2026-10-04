"""Mostra, para o MESMO registro, a resposta SEM response_model de saída (baseline :8001) e COM response_model dedicado (:8000).

"Sem" = a rota devolve o objeto da tabela — ou declara response_model=<a própria tabela>, como no Starter Kit,
o que filtra exatamente nada.

Evidência do Exercício 2: o que vaza quando a rota devolve o objeto da tabela.
Uso: python scripts/compare_response_model.py > evidence/ex02_templates_xss/sem_vs_com_response_model.txt
"""
import json
from pathlib import Path

import httpx2 as httpx

LOCAL = Path(__file__).resolve().parent.parent / "evidence" / ".local"
creds = json.loads((LOCAL / "demo_credentials.json").read_text())


def token(base: str, email: str, password: str) -> dict:
    r = httpx.post(f"{base}/user/signin", data={"username": email, "password": password}, timeout=10)
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def show(title: str, base: str, headers: dict, path: str) -> None:
    r = httpx.get(f"{base}{path}", headers=headers, timeout=10)
    print(f"\n### {title}\n$ GET {path}  -> HTTP {r.status_code}")
    print(json.dumps(r.json(), indent=2, ensure_ascii=False))


email = "helena@demo.clinica.com.br"
before = token("http://127.0.0.1:8001", email, "Baseline-Pass-1!")
after = token("http://127.0.0.1:8000", email, creds[email]["password"])

print("# Mesmo registro, duas versões. A tabela tem campos internos (created_from_ip, internal_audit_note...) e CPF completo.")
show("SEM response_model dedicado (response_model = a própria tabela, como no Starter Kit) — versão vulnerável", "http://127.0.0.1:8001", before, "/appointment/1")
show("COM response_model dedicado (AppointmentPublic: whitelist de campos) — versão corrigida", "http://127.0.0.1:8000", after, "/appointment/1")
show("SEM response_model dedicado — paciente", "http://127.0.0.1:8001", before, "/patient/1")
show("COM response_model dedicado (PatientPublic: CPF mascarado) — paciente", "http://127.0.0.1:8000", after, "/patient/1")

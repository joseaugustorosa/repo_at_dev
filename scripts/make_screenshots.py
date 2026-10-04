"""Gera os HTMLs das páginas da recepção para capturas de tela (Exercício 2).

Roda a aplicação EM PROCESSO com banco em memória e dados fictícios (nada toca o clinica.db).
Cria três arquivos autocontidos (CSS embutido) em evidence/ex02_templates_xss/:
  agenda_normal.html          agenda do dia, dados normais
  agenda_xss_escapado.html    agenda com payload XSS PERSISTIDO direto no banco (dado legado) -> exibido como texto
  login.html                  tela de login
O script scripts/collect_evidence.sh converte cada HTML em PNG com o Chrome headless.
"""
import os
import re
import secrets
import sys
from pathlib import Path

import bcrypt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "evidence" / "ex02_templates_xss"
OUT.mkdir(parents=True, exist_ok=True)

os.environ.update({
    "APP_ENV": "test", "DATABASE_URL": "sqlite://", "JWT_SECRET_KEY": secrets.token_urlsafe(48),
    "MFA_MASTER_KEY": secrets.token_urlsafe(48), "BCRYPT_ROUNDS": "4", "COOKIE_SECURE": "false",
    "ENABLE_DOCS": "true", "LOGIN_RATE_LIMIT": "50", "LOGIN_RATE_LIMIT_PER_IP": "50",
    "LOGIN_RATE_LIMIT_PER_ACCOUNT": "50",
})

from datetime import datetime, timedelta  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel  # noqa: E402

from database.connection import engine  # noqa: E402
from main import app  # noqa: E402
from models.appointments import Appointment  # noqa: E402
from models.patients import Patient  # noqa: E402
from models.users import Role, User  # noqa: E402

SQLModel.metadata.create_all(engine)
PASSWORD = secrets.token_urlsafe(14)
CSS = (ROOT / "static" / "app.css").read_text()


def inline(html: str) -> str:
    return re.sub(r'<link rel="stylesheet" href="/static/app.css">', f"<style>{CSS}</style>", html)


def seed(session: Session) -> User:
    pwd = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(4)).decode()
    recep = User(name="Rita Recepção", email="rita@demo.clinica.com.br", password_hash=pwd, role=Role.recepcionista)
    doc = User(name="Dra Helena Costa", email="helena@demo.clinica.com.br", password_hash=pwd, role=Role.profissional)
    session.add_all([recep, doc])
    session.commit()
    names = ["Maria da Silva", "João Pereira", '"><img src=x onerror=alert(1)>']
    reasons = ["Retorno de exames", "Consulta de rotina", '<script>alert("xss armazenado")</script>']
    day = (datetime.now() + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    while day.weekday() >= 5:
        day += timedelta(days=1)
    for i, (n, r) in enumerate(zip(names, reasons)):
        p = Patient(name=n, cpf=f"0000000000{i}", phone="11999990000", professional_id=doc.id)
        session.add(p)
        session.commit()
        session.refresh(p)
        # grava direto no banco: simula dado legado/malicioso que NÃO passou pela validação de entrada
        session.add(Appointment(patient_id=p.id, professional_id=doc.id, date_time=day.replace(hour=9 + i),
                                reason=r, notes="anotação clínica (não aparece na agenda)"))
    session.commit()
    return recep, day


with Session(engine) as s:
    recep, day = seed(s)
    email = recep.email

client = TestClient(app)
login_page = client.get("/web/login")
(OUT / "login.html").write_text(inline(login_page.text))
csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text).group(1)
r = client.post("/web/login", data={"username": email, "password": PASSWORD, "mfa_code": "", "csrf_token": csrf},
                follow_redirects=False)
assert r.status_code == 303, r.text
page = client.get(f"/web/agenda?day={day.date().isoformat()}")
assert page.status_code == 200
html = inline(page.text)
(OUT / "agenda_xss_escapado.html").write_text(html)

# versão "normal": só as duas primeiras linhas (sem o registro com payload)
with Session(engine) as s:
    bad = s.exec(__import__("sqlmodel").select(Appointment).where(Appointment.reason.like("<script>%"))).first()
    s.delete(bad)
    s.commit()
normal = client.get(f"/web/agenda?day={day.date().isoformat()}")
(OUT / "agenda_normal.html").write_text(inline(normal.text))
print("gerados:", *(p.name for p in sorted(OUT.glob("*.html"))))
print("payload <script> cru na página?", "<script>alert" in page.text, "| texto escapado presente?", "&lt;script&gt;" in page.text)

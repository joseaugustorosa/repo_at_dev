"""!!! APLICAÇÃO PROPOSITALMENTE VULNERÁVEL — SOMENTE PARA DEMONSTRAÇÃO DO ANTES/DEPOIS !!!

Reconstrução didática do estado do código ANTES do Exercício 9: parte do Starter Kit da
disciplina (segredo JWT fixo, `User` usado como corpo da requisição, `response_model`
devolvendo a tabela inteira, rotas por ID sem ownership) acrescido dos padrões que o
Exercício 8 manda identificar (SQL por f-string, HTML sem escape, CORS "*").

NUNCA execute fora de localhost. Está excluída do CI (Bandit/Trivy) de propósito: o scan
dela é usado como evidência de que o gate DETECTA estas falhas.
Execução:  uvicorn app:app --port 8001   (dentro desta pasta)
"""
import time
from pathlib import Path
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jinja2 import Template
from sqlalchemy import text
from sqlmodel import Field, Session, SQLModel, create_engine, select

SECRET_KEY = "chave_secreta_super_segura_para_estudantes"  # A02/A07: segredo fixo, vindo do starter kit
BASELINE_PASSWORD = "Baseline-Pass-1!"

DB = Path(__file__).resolve().parent.parent.parent / ".local" / "baseline.db"
DB.parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(f"sqlite:///{DB}", connect_args={"check_same_thread": False})
oauth2 = OAuth2PasswordBearer(tokenUrl="/user/signin")


class User(SQLModel, table=True):  # também serve de corpo do signup => mass assignment de `role`
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(index=True, unique=True)
    password: str
    role: str = "recepcionista"


class Patient(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    cpf: str
    phone: str
    professional_id: int


class Appointment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    patient_id: int
    professional_id: int  # vem do corpo da requisição
    date_time: str
    status: str = "agendada"
    reason: str
    notes: Optional[str] = None
    created_from_ip: Optional[str] = "10.0.0.5"  # campos internos de auditoria...
    internal_audit_note: Optional[str] = "revisar-depois"  # ...que a API devolve junto


def seed() -> None:
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        if s.exec(select(User)).first():
            return
        pwd = bcrypt.hashpw(BASELINE_PASSWORD.encode(), bcrypt.gensalt(4)).decode()
        for name, email, role in [("Admin Demo", "admin@demo.clinica.com.br", "admin"),
                                  ("Rita Recepcao", "recepcao@demo.clinica.com.br", "recepcionista"),
                                  ("Dra Helena Costa", "helena@demo.clinica.com.br", "profissional"),
                                  ("Dr Paulo Mendes", "paulo@demo.clinica.com.br", "profissional")]:
            s.add(User(name=name, email=email, password=pwd, role=role))
        s.commit()
        for i, (name, cpf, owner) in enumerate([("Maria da Silva", "52998224725", 3), ("Joao Pereira", "16899535009", 3),
                                                ("Ana Beatriz Lima", "11144477735", 4), ("Carlos Eduardo Rocha", "93541134780", 4)]):
            s.add(Patient(name=name, cpf=cpf, phone=f"1199900000{i}", professional_id=owner))
        s.commit()
        for pid, owner, when, reason, notes in [(1, 3, "2026-10-05T09:00:00", "Retorno de exames", "Paciente refere melhora. PA 120/80."),
                                                (2, 3, "2026-10-05T10:00:00", "Consulta de rotina", "Solicitado hemograma completo."),
                                                (3, 4, "2026-10-05T14:00:00", "Avaliacao inicial", "Queixa de cefaleia ha 2 semanas."),
                                                (4, 4, "2026-10-06T09:00:00", "Retorno", None)]:
            s.add(Appointment(patient_id=pid, professional_id=owner, date_time=when, reason=reason, notes=notes))
        s.commit()


seed()
app = FastAPI(title="BASELINE VULNERÁVEL (não usar)")
# A05: CORS com curinga + credenciais; nenhum cabeçalho de segurança; nenhum rate limit
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def get_session():
    with Session(engine) as session:
        yield session


def current_user(token: str = Depends(oauth2), session: Session = Depends(get_session)) -> User:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_aud": False})
    except Exception:  # noqa: BLE001 — `except:` genérico, como no starter kit
        raise HTTPException(403, "Token inválido ou expirado")
    if data.get("expires", 0) < time.time():
        raise HTTPException(403, "Token inválido ou expirado")
    user = session.exec(select(User).where(User.email == data["user"])).first()
    if not user:
        raise HTTPException(401, "Usuário não encontrado")
    return user


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/user/signup")
def signup(user: User, session: Session = Depends(get_session)):  # sem autenticação e com `role` no corpo
    user.password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt(4)).decode()
    session.add(user)
    session.commit()
    return {"message": "Usuário criado com sucesso!"}


@app.post("/user/signin")
def signin(form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == form.username)).first()
    if not user or not bcrypt.checkpw(form.password.encode(), user.password.encode()):
        raise HTTPException(401, "Credenciais inválidas.")
    token = jwt.encode({"user": user.email, "expires": time.time() + 3600}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "token_type": "Bearer"}


@app.get("/user/")
def list_users(me: User = Depends(current_user), session: Session = Depends(get_session)):
    if me.role != "admin":
        raise HTTPException(403, "Acesso negado.")
    return session.exec(select(User)).all()  # devolve também o hash da senha


@app.get("/patient/search")
def search_patients(name: str, me: User = Depends(current_user), session: Session = Depends(get_session)):
    query = f"SELECT * FROM patient WHERE name LIKE '%{name}%'"  # A03: SQL montado por f-string
    return [dict(r._mapping) for r in session.execute(text(query)).all()]


@app.get("/patient/{patient_id}", response_model=Patient)
def read_patient(patient_id: int, me: User = Depends(current_user), session: Session = Depends(get_session)):
    patient = session.get(Patient, patient_id)  # A01/BOLA: nenhum teste de dono
    if not patient:
        raise HTTPException(404, "Paciente não encontrado.")
    return patient


@app.get("/appointment/", response_model=list[Appointment])
def list_appointments(me: User = Depends(current_user), session: Session = Depends(get_session)):
    if me.role == "profissional":
        return session.exec(select(Appointment).where(Appointment.professional_id == me.id)).all()
    return session.exec(select(Appointment)).all()


@app.post("/appointment/new", response_model=Appointment)
def create_appointment(data: Appointment, me: User = Depends(current_user), session: Session = Depends(get_session)):
    session.add(data)  # o corpo é gravado como veio (professional_id, status, campos internos...)
    session.commit()
    session.refresh(data)
    return data


@app.get("/appointment/{appointment_id}", response_model=Appointment)
def read_appointment(appointment_id: int, me: User = Depends(current_user), session: Session = Depends(get_session)):
    appointment = session.get(Appointment, appointment_id)  # A01/BOLA: só confere "autenticado"
    if not appointment:
        raise HTTPException(404, "Consulta não encontrada.")
    return appointment


@app.put("/appointment/{appointment_id}", response_model=Appointment)
def update_appointment(appointment_id: int, data: dict, me: User = Depends(current_user),
                       session: Session = Depends(get_session)):
    appointment = session.get(Appointment, appointment_id)
    if not appointment:
        raise HTTPException(404, "Consulta não encontrada.")
    for key, value in data.items():  # mass assignment: qualquer campo
        setattr(appointment, key, value)
    session.add(appointment)
    session.commit()
    session.refresh(appointment)
    return appointment


AGENDA = Template("""<html><body><h1>Agenda</h1><table>
{% for a in items %}<tr><td>{{ a.date_time }}</td><td>{{ a.patient | safe }}</td><td>{{ a.reason | safe }}</td></tr>{% endfor %}
</table></body></html>""")  # A03/XSS: `| safe` desliga o escape


@app.get("/web/agenda", response_class=HTMLResponse)
def agenda(me: User = Depends(current_user), session: Session = Depends(get_session)):
    rows = session.exec(select(Appointment, Patient).join(Patient, Appointment.patient_id == Patient.id)).all()
    return AGENDA.render(items=[{"date_time": a.date_time, "patient": p.name, "reason": a.reason} for a, p in rows])

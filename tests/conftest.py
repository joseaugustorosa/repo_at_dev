"""Fixtures compartilhadas. Segredos de teste são gerados a cada execução —
nenhum valor sensível fixo no repositório."""
import os
import secrets

import bcrypt

# --- Ambiente de teste: definido ANTES de importar a aplicação ---------------
LAB_SECRET = secrets.token_urlsafe(32)
os.environ.update(
    {
        "APP_ENV": "test",
        "DATABASE_URL": "sqlite://",  # banco em memória (StaticPool em database/connection.py)
        "JWT_SECRET_KEY": secrets.token_urlsafe(48),
        "MFA_MASTER_KEY": secrets.token_urlsafe(48),
        "BCRYPT_ROUNDS": "4",  # só nos testes, para acelerar (produção exige >= 12)
        "LAB_CLIENT_ID": "laboratorio-parceiro",
        "LAB_CLIENT_SECRET_HASH": bcrypt.hashpw(LAB_SECRET.encode(), bcrypt.gensalt(4)).decode(),
        "LAB_ALLOWED_SCOPES": '["availability:read"]',
        "CORS_ALLOWED_ORIGINS": '["http://localhost:3000"]',
        "COOKIE_SECURE": "false",
        "ENABLE_DOCS": "true",
        "LOGIN_RATE_LIMIT": "5",
        "LOGIN_RATE_LIMIT_PER_IP": "20",
        "LOGIN_RATE_LIMIT_PER_ACCOUNT": "15",
        "DEFAULT_RATE_LIMIT": "10000",
    }
)

from datetime import datetime  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel  # noqa: E402

from auth import mfa  # noqa: E402
from auth.hash_password import HashPassword  # noqa: E402
from auth.jwt_handler import TokenUse, access_ttl, create_token  # noqa: E402
from core.rate_limit import limiter  # noqa: E402
from database.connection import engine  # noqa: E402
from main import app  # noqa: E402
from models.appointments import Appointment  # noqa: E402
from models.patients import Patient  # noqa: E402
from models.users import Role, User  # noqa: E402
from tests.helpers import PASSWORD, cpf_check_digits, next_slot  # noqa: E402

hasher = HashPassword()


@pytest.fixture(autouse=True)
def fresh_state():
    """Banco e contadores de rate limit zerados a cada teste."""
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    limiter.reset()
    yield


@pytest.fixture
def session():
    with Session(engine) as s:
        yield s


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def make_user(session):
    def _make(role: Role, email: str | None = None, name: str = "Usuario Teste") -> User:
        user = User(
            name=name,
            email=email or f"{role.value}-{secrets.token_hex(3)}@clinica.com.br",
            password_hash=hasher.create_hash(PASSWORD),
            role=role,
            mfa_seed=mfa.new_seed() if role is Role.admin else None,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    return _make


def token_for(user: User) -> str:
    return create_token(
        subject=str(user.id),
        token_use=TokenUse.access,
        ttl=access_ttl(),
        extra_claims={"role": user.role.value},
    )


@pytest.fixture
def auth():
    """Cabeçalho Authorization para um usuário (emite o JWT direto, sem passar pelo login)."""

    def _auth(user: User) -> dict[str, str]:
        return {"Authorization": f"Bearer {token_for(user)}"}

    return _auth


@pytest.fixture
def make_patient(session):
    counter = iter(range(10_000))

    def _make(owner: User, name: str = "Maria Souza") -> Patient:
        # CPFs válidos gerados deterministicamente a partir de um contador
        base = f"{next(counter) + 100000000:09d}"
        patient = Patient(
            name=name,
            cpf=base + cpf_check_digits(base),
            phone="11999998888",
            professional_id=owner.id,
        )
        session.add(patient)
        session.commit()
        session.refresh(patient)
        return patient

    return _make





@pytest.fixture
def make_appointment(session):
    def _make(professional: User, patient: Patient, when: datetime | None = None, **kw) -> Appointment:
        appt = Appointment(
            patient_id=patient.id,
            professional_id=professional.id,
            date_time=when or next_slot(),
            reason=kw.pop("reason", "Consulta de rotina"),
            **kw,
        )
        session.add(appt)
        session.commit()
        session.refresh(appt)
        return appt

    return _make

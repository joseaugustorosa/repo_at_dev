"""Exercício 11 — persistência segura: SQLModel, DI de sessão, credenciais via BaseSettings/.env."""
import re
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from core.config import Settings
from database.connection import get_session
from main import app
from models.users import Role
from tests.helpers import next_slot

ROOT = Path(__file__).resolve().parent.parent


def test_settings_exigem_credenciais_do_ambiente(monkeypatch):
    """Sem .env/variáveis a aplicação NÃO sobe com valores padrão inseguros."""
    for var in ("DATABASE_URL", "JWT_SECRET_KEY", "MFA_MASTER_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    missing = {e["loc"][0] for e in exc.value.errors()}
    assert {"database_url", "jwt_secret_key", "mfa_master_key"} <= missing


def test_chave_jwt_fraca_e_recusada():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url="sqlite://", jwt_secret_key="curta", mfa_master_key="x" * 40)  # type: ignore[call-arg]


def test_producao_exige_endurecimento():
    """Cada variação quebra exatamente UMA regra; a última (tudo certo) é aceita."""
    base = dict(_env_file=None, database_url="sqlite://", jwt_secret_key="k" * 40, mfa_master_key="m" * 40,
                app_env="production", bcrypt_rounds=12, cookie_secure=True, enable_docs=False)
    for broken in ({"bcrypt_rounds": 4}, {"cookie_secure": False}, {"enable_docs": True}):
        with pytest.raises(ValidationError):
            Settings(**{**base, **broken})  # type: ignore[arg-type]
    Settings(**base)  # type: ignore[arg-type]


def test_senhas_do_settings_nao_vazam_no_repr():
    s = Settings(_env_file=None, database_url="sqlite://", jwt_secret_key="s" * 40, mfa_master_key="m" * 40)  # type: ignore[call-arg]
    assert "s" * 40 not in repr(s) and "m" * 40 not in repr(s)


def test_sessao_e_injetada_por_dependencia(client, make_user, auth):
    """Trocar `get_session` por outro banco prova que as rotas usam a sessão injetada."""
    other = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(other)  # banco vazio, separado do padrão

    def other_session():
        with Session(other) as sess:
            yield sess

    admin = make_user(Role.admin)  # existe só no banco "padrão"
    app.dependency_overrides[get_session] = other_session
    try:
        # token válido, mas o usuário não existe NESTE banco => 401 (prova que a sessão injetada foi usada)
        assert client.get("/user/", headers=auth(admin)).status_code == 401
    finally:
        app.dependency_overrides.clear()
    assert client.get("/user/", headers=auth(admin)).status_code == 200


def test_horario_duplicado_do_mesmo_profissional_retorna_409(client, make_user, make_patient, auth):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    body = {"patient_id": patient.id, "date_time": next_slot().isoformat(), "reason": "Consulta"}
    assert client.post("/appointment/new", json=body, headers=auth(doctor)).status_code == 201
    assert client.post("/appointment/new", json=body, headers=auth(doctor)).status_code == 409


def test_horario_cancelado_pode_ser_reutilizado(client, make_user, make_patient, auth):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    body = {"patient_id": patient.id, "date_time": next_slot().isoformat(), "reason": "Consulta"}
    first = client.post("/appointment/new", json=body, headers=auth(doctor)).json()
    assert client.delete(f"/appointment/{first['id']}", headers=auth(doctor)).status_code == 200
    assert client.post("/appointment/new", json=body, headers=auth(doctor)).status_code == 201


def test_cpf_duplicado_retorna_409(client, make_user, auth):
    recep, doctor = make_user(Role.recepcionista), make_user(Role.profissional)
    body = {"name": "Maria Souza", "cpf": "529.982.247-25", "phone": "11999998888", "professional_id": doctor.id}
    assert client.post("/patient/new", json=body, headers=auth(recep)).status_code == 201
    assert client.post("/patient/new", json=body, headers=auth(recep)).status_code == 409


def test_codigo_nao_contem_credenciais_embutidas():
    """Guarda estática simples (complementa Bandit B105/B106 e o scan de segredos do Trivy)."""
    pattern = re.compile(
        r"""(?ix) \b( \w*(secret|password|passwd|api[_-]?key)\w* | token ) \s*[:=]\s* ["'][^"'\s]{8,}["']"""
    )
    offenders = []
    for folder in ("auth", "core", "database", "models", "routes", "main.py"):
        target = ROOT / folder
        files = [target] if target.is_file() else target.rglob("*.py")
        for py in files:
            for n, line in enumerate(py.read_text().splitlines(), 1):
                if pattern.search(line) and "Form(" not in line and "Field(" not in line:
                    offenders.append(f"{py.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, "\n".join(offenders)


def test_env_example_nao_tem_segredos_reais_e_env_real_esta_no_gitignore():
    example = (ROOT / ".env.example").read_text()
    assert "<gerar-valor-aleatorio>" in example and "<hash-bcrypt" in example
    assert not re.search(r"\$2[aby]\$\d\d\$", example)  # nenhum hash bcrypt real
    assert re.search(r"^\.env$", (ROOT / ".gitignore").read_text(), re.M)


def test_consulta_usa_parametros_ligados(session):
    """O SQL gerado contém placeholders, nunca o valor do usuário embutido."""
    from models.patients import Patient

    stmt = select(Patient).where(Patient.name == "x' OR '1'='1")
    compiled = stmt.compile()
    assert "x' OR '1'='1" not in str(compiled)
    assert list(compiled.params.values()) == ["x' OR '1'='1"]

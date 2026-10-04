"""Exercício 6 — autenticação (bcrypt, JWT com expiração, MFA) e autorização (RBAC + ownership)."""
import base64
import json
from datetime import timedelta

import jwt
import pytest

from auth import mfa
from auth.jwt_handler import TokenUse, create_token, decode_token
from core.config import get_settings
from models.users import Role
from tests.helpers import signin


# --------------------- o teste pedido no enunciado ---------------------------
@pytest.mark.parametrize("role", [Role.recepcionista, Role.profissional])
def test_usuario_sem_papel_admin_nao_acessa_rota_restrita_a_admin(client, make_user, auth, role):
    """Não-admin é barrado (403) nas rotas exclusivas de administradores."""
    user = make_user(role)
    assert client.get("/user/", headers=auth(user)).status_code == 403
    payload = {"name": "Novo Admin", "email": "novo@clinica.com.br", "password": "Outra-Senha-123", "role": "admin"}
    assert client.post("/user/signup", json=payload, headers=auth(user)).status_code == 403


def test_admin_acessa_rota_restrita(client, make_user, auth):
    admin = make_user(Role.admin)
    assert client.get("/user/", headers=auth(admin)).status_code == 200


def test_sem_token_retorna_401(client):
    r = client.get("/user/")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


# ----------------------------- senha / bcrypt --------------------------------
def test_senha_e_armazenada_com_hash_bcrypt(client, make_user, auth, session):
    admin = make_user(Role.admin)
    payload = {"name": "Nova Pessoa", "email": "nova@clinica.com.br", "password": "Outra-Senha-123", "role": "recepcionista"}
    r = client.post("/user/signup", json=payload, headers=auth(admin))
    assert r.status_code == 201
    from models.users import User
    from sqlmodel import select

    stored = session.exec(select(User).where(User.email == "nova@clinica.com.br")).one()
    assert stored.password_hash.startswith("$2b$")
    assert "Outra-Senha-123" not in stored.password_hash
    assert "password" not in r.text


def test_login_devolve_jwt_com_expiracao_e_claims_corretas(client, make_user):
    user = make_user(Role.profissional)
    r = signin(client, user.email)
    assert r.status_code == 200
    claims = decode_token(r.json()["access_token"])
    assert claims["token_use"] == "access" and claims["role"] == "profissional"
    assert claims["sub"] == str(user.id)
    assert 0 < claims["exp"] - claims["iat"] <= 30 * 60  # TTL curto, nunca "sem expiração"


def test_login_invalido_usa_mensagem_generica(client, make_user):
    user = make_user(Role.profissional)
    wrong_pass = signin(client, user.email, "senha-errada-123")
    unknown = signin(client, "ninguem@clinica.com.br")
    assert wrong_pass.status_code == unknown.status_code == 401
    assert wrong_pass.json() == unknown.json()  # não revela se o e-mail existe


# ------------------------------- JWT inválido --------------------------------
def _forge(payload: dict, key: str, alg: str = "HS256") -> str:
    return jwt.encode(payload, key, algorithm=alg)


def _claims(user, **over):
    s = get_settings()
    import time

    base = {
        "iss": s.jwt_issuer, "aud": s.jwt_audience, "sub": str(user.id), "iat": int(time.time()),
        "nbf": int(time.time()), "exp": int(time.time()) + 600, "jti": "x", "token_use": "access",
        "role": user.role.value,
    }
    return {**base, **over}


def test_token_expirado_e_rejeitado(client, make_user):
    user = make_user(Role.admin)
    token = create_token(subject=str(user.id), token_use=TokenUse.access, ttl=timedelta(seconds=-5),
                         extra_claims={"role": "admin"})
    assert client.get("/user/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_com_assinatura_errada_e_rejeitado(client, make_user):
    user = make_user(Role.admin)
    token = _forge(_claims(user), "chave-do-atacante-com-mais-de-32-caracteres!!")
    assert client.get("/user/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_alg_none_e_rejeitado(client, make_user):
    user = make_user(Role.admin)
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    token = f'{b64({"alg": "none", "typ": "JWT"})}.{b64(_claims(user))}.'
    assert client.get("/user/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_de_outra_audiencia_e_rejeitado(client, make_user):
    user = make_user(Role.admin)
    secret = get_settings().jwt_secret_key.get_secret_value()
    token = _forge(_claims(user, aud="outra-api"), secret)
    assert client.get("/user/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_alterado_para_papel_admin_nao_eleva_privilegio(client, make_user):
    """Mesmo com assinatura válida, o papel do BANCO manda: claim divergente => 401."""
    doctor = make_user(Role.profissional)
    secret = get_settings().jwt_secret_key.get_secret_value()
    token = _forge(_claims(doctor, role="admin"), secret)
    assert client.get("/user/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_usuario_desativado_perde_acesso_imediatamente(client, make_user, auth):
    admin, doctor = make_user(Role.admin), make_user(Role.profissional)
    headers = auth(doctor)
    assert client.get("/user/me", headers=headers).status_code == 200
    assert client.patch(f"/user/{doctor.id}/deactivate", headers=auth(admin)).status_code == 200
    assert client.get("/user/me", headers=headers).status_code == 401


# --------------------------------- MFA ---------------------------------------
def test_admin_exige_mfa_e_nao_recebe_access_token_so_com_senha(client, make_user):
    admin = make_user(Role.admin)
    r = signin(client, admin.email)
    assert r.status_code == 200
    body = r.json()
    assert body["mfa_required"] is True and "access_token" not in body
    # o token de desafio MFA não serve como credencial de API
    assert client.get("/user/", headers={"Authorization": f"Bearer {body['mfa_token']}"}).status_code == 401


def test_mfa_codigo_correto_emite_token_e_replay_e_negado(client, make_user, session):
    admin = make_user(Role.admin)
    challenge = signin(client, admin.email).json()["mfa_token"]
    code = mfa.current_code(admin)

    ok = client.post("/user/mfa/verify", json={"mfa_token": challenge, "code": code})
    assert ok.status_code == 200
    assert client.get("/user/", headers={"Authorization": f"Bearer {ok.json()['access_token']}"}).status_code == 200

    replay = client.post("/user/mfa/verify", json={"mfa_token": challenge, "code": code})
    assert replay.status_code == 401  # mesmo código não pode ser reutilizado


def test_mfa_codigo_errado_e_negado(client, make_user):
    admin = make_user(Role.admin)
    challenge = signin(client, admin.email).json()["mfa_token"]
    r = client.post("/user/mfa/verify", json={"mfa_token": challenge, "code": "000000"})
    assert r.status_code == 401


# ------------------------- ownership (RBAC + ABAC) ---------------------------
def test_profissional_nao_le_consulta_de_outro_profissional(client, make_user, make_patient, make_appointment, auth):
    dr_a, dr_b = make_user(Role.profissional), make_user(Role.profissional)
    appt_a = make_appointment(dr_a, make_patient(dr_a))
    assert client.get(f"/appointment/{appt_a.id}", headers=auth(dr_a)).status_code == 200
    assert client.get(f"/appointment/{appt_a.id}", headers=auth(dr_b)).status_code == 404


def test_profissional_nao_agenda_para_paciente_de_outro(client, make_user, make_patient, auth):
    dr_a, dr_b = make_user(Role.profissional), make_user(Role.profissional)
    patient_a = make_patient(dr_a)
    from tests.helpers import next_slot

    r = client.post(
        "/appointment/new",
        json={"patient_id": patient_a.id, "date_time": next_slot().isoformat(), "reason": "Consulta"},
        headers=auth(dr_b),
    )
    assert r.status_code == 404


def test_recepcionista_nao_cria_consulta(client, make_user, make_patient, auth):
    recep, doctor = make_user(Role.recepcionista), make_user(Role.profissional)
    patient = make_patient(doctor)
    from tests.helpers import next_slot

    r = client.post(
        "/appointment/new",
        json={"patient_id": patient.id, "date_time": next_slot().isoformat(), "reason": "Consulta"},
        headers=auth(recep),
    )
    assert r.status_code == 403


# ------------------- MFA também na página web (mesma regra, mesmo código) ----
def test_web_admin_exige_codigo_mfa_e_aceita_o_correto(client, make_user):
    from tests.helpers import web_login

    admin = make_user(Role.admin)
    sem_codigo = web_login(client, admin.email)
    assert sem_codigo.status_code == 401 and "clinica_session" not in sem_codigo.headers.get("set-cookie", "")
    errado = web_login(client, admin.email, mfa_code="000000")
    assert errado.status_code == 401
    certo = web_login(client, admin.email, mfa_code=mfa.current_code(admin))
    assert certo.status_code == 303 and "clinica_session" in certo.headers["set-cookie"]


def test_web_login_com_senha_errada_nao_cria_sessao(client, make_user):
    from tests.helpers import web_login

    recep = make_user(Role.recepcionista)
    r = web_login(client, recep.email, password="senha-errada-123")
    assert r.status_code == 401 and "clinica_session" not in r.headers.get("set-cookie", "")
    assert client.get("/web/agenda", follow_redirects=False).status_code == 303

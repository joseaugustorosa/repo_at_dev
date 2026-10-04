"""Exercício 7 — Client Credentials, escopos OAuth e claims que separam laboratório de usuário."""
from datetime import date, timedelta

import pytest

from auth.jwt_handler import decode_token
from models.users import Role
from tests.conftest import LAB_SECRET
from tests.helpers import next_slot

TOKEN_URL = "/oauth/token"


def lab_token(client, **over) -> dict:
    data = {"grant_type": "client_credentials", "client_id": "laboratorio-parceiro",
            "client_secret": LAB_SECRET, "scope": "availability:read", **over}
    return client.post(TOKEN_URL, data=data)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_laboratorio_obtem_token_com_escopo_e_claims_de_maquina(client):
    r = lab_token(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer" and body["scope"] == "availability:read"
    assert body["expires_in"] == 600  # TTL curto para token M2M
    assert "refresh_token" not in body  # RFC 6749 §4.4.3
    claims = decode_token(body["access_token"])
    assert claims["token_use"] == "m2m"
    assert claims["scope"] == "availability:read"
    assert claims["client_id"] == claims["sub"] == "laboratorio-parceiro"
    assert "role" not in claims  # não é uma pessoa e não tem papel


@pytest.mark.parametrize(
    "over,status,error",
    [
        ({"client_secret": "segredo-errado"}, 401, "invalid_client"),
        ({"client_id": "outro-cliente"}, 401, "invalid_client"),
        ({"grant_type": "password"}, 400, "unsupported_grant_type"),
        ({"scope": "availability:read patients:read"}, 400, "invalid_scope"),
        ({"scope": "admin"}, 400, "invalid_scope"),
    ],
)
def test_token_endpoint_recusa_pedidos_invalidos(client, over, status, error):
    r = lab_token(client, **over)
    assert r.status_code == status
    assert r.json()["error"] == error
    assert "access_token" not in r.json()


def test_laboratorio_consulta_horarios_livres_sem_dados_de_paciente(client, make_user, make_patient, make_appointment):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor, name="Paciente Sigiloso")
    booked = next_slot(3, hour=9, minute=30)
    make_appointment(doctor, patient, when=booked, reason="Motivo sigiloso")

    token = lab_token(client).json()["access_token"]
    r = client.get(
        "/availability/",
        params={"professional_id": doctor.id, "day": booked.date().isoformat()},
        headers=bearer(token),
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"professional_id", "day", "slot_minutes", "available_slots"}
    assert "09:30:00" not in body["available_slots"]  # horário ocupado não é oferecido
    assert "10:00:00" in body["available_slots"]
    assert "Sigiloso" not in r.text


@pytest.mark.parametrize(
    "method,url",
    [("get", "/patient/"), ("get", "/appointment/"), ("get", "/appointment/agenda"),
     ("get", "/user/"), ("get", "/user/me"), ("get", "/patient/search?name=ana")],
)
def test_token_do_laboratorio_nao_acessa_rotas_de_usuarios(client, method, url):
    """Mesmo que o token do laboratório vaze, ele só serve para /availability."""
    token = lab_token(client).json()["access_token"]
    r = getattr(client, method)(url, headers=bearer(token))
    assert r.status_code == 403


def test_token_de_profissional_nao_acessa_rota_do_laboratorio(client, make_user, auth):
    doctor = make_user(Role.profissional)
    r = client.get(
        "/availability/",
        params={"professional_id": doctor.id, "day": (date.today() + timedelta(days=1)).isoformat()},
        headers=auth(doctor),
    )
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers["www-authenticate"]


def test_token_m2m_com_outro_escopo_nao_acessa_availability(client):
    from auth.jwt_handler import TokenUse, create_token, m2m_ttl

    weak = create_token(subject="laboratorio-parceiro", token_use=TokenUse.m2m, ttl=m2m_ttl(),
                        extra_claims={"scope": "reports:read"})
    r = client.get("/availability/", params={"professional_id": 1, "day": date.today().isoformat()},
                   headers=bearer(weak))
    assert r.status_code == 403


def test_availability_valida_janela_de_datas_e_profissional(client):
    token = lab_token(client).json()["access_token"]
    far = (date.today() + timedelta(days=400)).isoformat()
    assert client.get("/availability/", params={"professional_id": 1, "day": far},
                      headers=bearer(token)).status_code == 422
    near = (date.today() + timedelta(days=1)).isoformat()
    assert client.get("/availability/", params={"professional_id": 999, "day": near},
                      headers=bearer(token)).status_code == 404

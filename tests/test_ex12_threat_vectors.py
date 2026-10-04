"""Exercício 12 — testes de segurança derivados do threat model (Exercício 4).

Cada teste aqui cobre um vetor da matriz `tests/threat_matrix.py` (IDs T-S1…T-X2) que
ainda não tinha cobertura nos testes dos exercícios anteriores. O primeiro teste
verifica que a própria matriz não aponta para testes inexistentes.
"""
import importlib
import logging
from datetime import datetime, timedelta

import pytest
from fastapi.routing import APIRoute

from auth.middleware import PUBLIC_PATHS, is_public
from main import app
from models.users import Role
from tests.helpers import next_slot, signin, web_login
from tests.threat_matrix import THREATS


def test_matriz_de_ameacas_aponta_apenas_para_testes_existentes():
    missing = []
    for threat_id, (_, tests) in THREATS.items():
        assert tests, f"{threat_id} sem teste associado"
        for ref in tests:
            module_name, *path = ref.split("::")  # módulo::[Classe::]função
            target = importlib.import_module(f"tests.{module_name}")
            for part in path:
                target = getattr(target, part, None)
            if target is None:
                missing.append(f"{threat_id}: {ref}")
    assert not missing, "\n".join(missing)


# ---------------------------- T-X1 deny-by-default ---------------------------
def _all_routes():
    """(método, caminho) de TODA rota da aplicação, incluindo as páginas HTML (fora do OpenAPI)."""
    from main import ROUTERS

    for router, prefix in ROUTERS:
        for route in router.routes:
            if isinstance(route, APIRoute):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    yield method, prefix + route.path.rstrip("/") + ("/" if route.path.endswith("/") and prefix else "")
    for route in app.routes:  # rotas declaradas direto na app ("/", "/health")
        if isinstance(route, APIRoute):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield method, route.path


def test_deny_by_default_em_todas_as_rotas(client):
    """Percorre TODAS as rotas registradas. Sem token, só a allowlist responde algo
    diferente de 401/redirect. Se alguém criar /novo-endpoint e esquecer a proteção, já nasce
    protegido pelo middleware; se alguém o puser na allowlist, este teste e o próximo avisam."""
    protected = 0
    for method, path in _all_routes():
        concrete = path.replace("{patient_id}", "1").replace("{appointment_id}", "1").replace("{user_id}", "1")
        r = client.request(method, concrete, follow_redirects=False)
        if is_public(concrete):
            continue
        expected = 303 if concrete.startswith("/web/") else 401  # páginas redirecionam ao login
        assert r.status_code == expected, f"{method} {concrete} respondeu {r.status_code} sem token"
        protected += 1
    assert protected >= 15  # garante que o teste realmente percorreu as rotas protegidas


def test_allowlist_publica_e_minima_e_explicita():
    assert PUBLIC_PATHS == {
        "/", "/health", "/user/signin", "/user/mfa/verify", "/oauth/token", "/web/login",
        "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect",
    }


# --------------------------------- T-R1 / T-R2 -------------------------------
def test_falha_de_login_e_negacao_de_acesso_geram_trilha_de_auditoria(client, make_user, auth, caplog):
    recep = make_user(Role.recepcionista)
    with caplog.at_level(logging.INFO, logger="clinica.audit"):
        signin(client, recep.email, "senha-errada-123")
        client.get("/user/", headers=auth(recep))  # 403: recepção tentando rota de admin
        client.get("/user/")  # sem token
    log = caplog.text
    assert '"event": "login"' in log and '"reason": "bad_password"' in log
    assert '"event": "access_denied"' in log and f'"user_id": {recep.id}' in log
    assert '"event": "auth_failed"' in log
    # a trilha NUNCA contém senha nem token
    assert "senha-errada-123" not in log and "Bearer" not in log


def test_alteracoes_de_consulta_geram_trilha_de_auditoria(
    client, make_user, make_patient, make_appointment, auth, caplog
):
    doctor, attacker = make_user(Role.profissional), make_user(Role.profissional)
    appt = make_appointment(doctor, make_patient(doctor))
    with caplog.at_level(logging.INFO, logger="clinica.audit"):
        client.put(f"/appointment/{appt.id}", json={"reason": "Reagendada"}, headers=auth(doctor))
        client.delete(f"/appointment/{appt.id}", headers=auth(doctor))
        client.get(f"/appointment/{appt.id}", headers=auth(attacker))  # tentativa BOLA
    assert '"event": "appointment_updated"' in caplog.text
    assert '"event": "appointment_cancelled"' in caplog.text
    assert '"event": "object_access_denied"' in caplog.text and f'"resource_id": {appt.id}' in caplog.text


# ------------------------------------ T-S2 -----------------------------------
def test_limite_por_conta_vale_mesmo_trocando_de_ip(client, make_user, monkeypatch):
    """Força bruta DISTRIBUÍDA (um IP novo a cada tentativa) contra UMA conta bate no teto por conta (15)."""
    user = make_user(Role.recepcionista)
    ips = iter(f"203.0.113.{i}" for i in range(1, 100))
    monkeypatch.setattr("core.rate_limit.client_ip", lambda request: next(ips))
    codes = [signin(client, user.email, "senha-errada-123").status_code for _ in range(17)]
    assert codes[:15] == [401] * 15 and codes[15:] == [429, 429]


def test_atacante_nao_consegue_travar_o_login_do_usuario_legitimo_em_outro_ip(client, make_user, monkeypatch):
    """Anti-DoS por lockout: o atacante esgota a cota (conta+IP) DELE; o usuário em outro IP continua entrando."""
    victim = make_user(Role.recepcionista)
    current_ip = {"v": "198.51.100.66"}  # atacante
    monkeypatch.setattr("core.rate_limit.client_ip", lambda request: current_ip["v"])
    attacker_codes = [signin(client, victim.email, "senha-errada-123").status_code for _ in range(7)]
    assert attacker_codes[-1] == 429  # o atacante foi contido...
    current_ip["v"] = "203.0.113.10"  # ...mas a vítima, no IP dela, entra normalmente
    assert signin(client, victim.email).status_code == 200


def test_credential_stuffing_de_um_ip_e_contido(client, monkeypatch):
    """Um IP testando MUITAS contas diferentes (nenhuma passa de 5) bate no limite por IP (20)."""
    codes = [signin(client, f"vitima{i}@clinica.com.br", "senha-errada-123").status_code for i in range(22)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429, 429]


def test_recepcao_atras_do_mesmo_nat_nao_e_bloqueada_por_logins_legitimos(client, make_user):
    """Contas diferentes, mesmo IP, poucas tentativas: dentro do limite por IP."""
    users = [make_user(Role.recepcionista) for _ in range(8)]
    assert all(signin(client, u.email).status_code == 200 for u in users)


# ------------------------------------ T-D2 -----------------------------------
@pytest.mark.parametrize("params", [{"limit": 100000}, {"limit": 0}, {"offset": -1}])
def test_paginacao_tem_teto_e_rejeita_valores_abusivos(client, make_user, auth, params):
    doctor = make_user(Role.profissional)
    assert client.get("/appointment/", params=params, headers=auth(doctor)).status_code == 422


# ------------------------------------ T-S4 -----------------------------------
def test_logout_exige_csrf(client, make_user):
    recep = make_user(Role.recepcionista)
    web_login(client, recep.email)
    assert client.post("/web/logout", data={"csrf_token": "falso"}, follow_redirects=False).status_code == 403


# ------------------------- regras de negócio com impacto de segurança ---------
def test_nao_agenda_no_passado_nem_fora_do_bloco_de_30_minutos(client, make_user, make_patient, auth):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    h = auth(doctor)
    past = (datetime.now() - timedelta(days=1)).replace(minute=0, second=0, microsecond=0)
    unaligned = next_slot().replace(minute=17)
    with_tz = next_slot().isoformat() + "+00:00"
    for when in (past.isoformat(), unaligned.isoformat(), with_tz):
        body = {"patient_id": patient.id, "date_time": when, "reason": "Consulta"}
        assert client.post("/appointment/new", json=body, headers=h).status_code == 422, when


def test_consulta_cancelada_nao_pode_ser_editada(client, make_user, make_patient, make_appointment, auth):
    doctor = make_user(Role.profissional)
    appt = make_appointment(doctor, make_patient(doctor))
    client.delete(f"/appointment/{appt.id}", headers=auth(doctor))
    r = client.put(f"/appointment/{appt.id}", json={"reason": "Tentando reabrir"}, headers=auth(doctor))
    assert r.status_code == 409

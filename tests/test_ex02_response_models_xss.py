"""Exercício 2 — response models (sem vazamento de campos internos) e página HTML segura."""
import re
from pathlib import Path

from models.appointments import Appointment, AppointmentPublic
from models.users import Role
from tests.helpers import next_slot, web_login

INTERNAL_FIELDS = {"created_by_user_id", "created_at", "updated_at", "created_from_ip", "internal_audit_note"}
PUBLIC_APPOINTMENT_FIELDS = {"id", "patient_id", "professional_id", "date_time", "status", "reason", "notes"}


def test_response_model_declara_apenas_campos_publicos():
    assert set(AppointmentPublic.model_fields) == PUBLIC_APPOINTMENT_FIELDS
    assert INTERNAL_FIELDS.isdisjoint(AppointmentPublic.model_fields)
    # a tabela TEM os campos internos — o response model é que os filtra
    assert INTERNAL_FIELDS <= set(Appointment.model_fields)


def test_nenhum_endpoint_de_consulta_vaza_campos_internos(client, make_user, make_patient, make_appointment, auth):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    appt = make_appointment(doctor, patient, internal_audit_note="NOTA-INTERNA", created_from_ip="10.0.0.9")
    h = auth(doctor)

    created = client.post(
        "/appointment/new",
        json={"patient_id": patient.id, "date_time": next_slot(5).isoformat(), "reason": "Retorno"},
        headers=h,
    )
    responses = [
        created,
        client.get(f"/appointment/{appt.id}", headers=h),
        client.get("/appointment/", headers=h),
        client.put(f"/appointment/{appt.id}", json={"reason": "Reagendada"}, headers=h),
        client.delete(f"/appointment/{appt.id}", headers=h),
    ]
    for r in responses:
        assert r.status_code in (200, 201), r.text
        body = r.json()
        for item in body if isinstance(body, list) else [body]:
            assert set(item) == PUBLIC_APPOINTMENT_FIELDS
        assert "NOTA-INTERNA" not in r.text and "10.0.0.9" not in r.text


def test_paciente_nunca_devolve_cpf_completo(client, make_user, make_patient, auth, session):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    r = client.get(f"/patient/{patient.id}", headers=auth(doctor))
    assert r.status_code == 200
    assert r.json()["cpf"].startswith("***.***.***-")
    assert patient.cpf not in r.text
    assert "created_by_user_id" not in r.json()


def test_usuario_nunca_devolve_hash_nem_semente_mfa(client, make_user, auth):
    admin = make_user(Role.admin)
    r = client.get("/user/", headers=auth(admin))
    assert r.status_code == 200
    assert "password" not in r.text and "mfa_seed" not in r.text and "$2b$" not in r.text


# ------------------------------- página HTML ---------------------------------
def _seed_agenda(make_user, make_patient, make_appointment, session, patient_name, reason):
    recep = make_user(Role.recepcionista)
    doctor = make_user(Role.profissional, name="Dra Helena")
    patient = make_patient(doctor, name=patient_name)
    patient.phone = "11988887777"
    session.add(patient)
    session.commit()
    appt = make_appointment(doctor, patient, reason=reason, notes="SEGREDO-CLINICO-123")
    return recep, appt


def test_pagina_agenda_exige_login(client):
    r = client.get("/web/agenda", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/web/login"


def test_pagina_agenda_escapa_conteudo_malicioso_persistido(
    client, make_user, make_patient, make_appointment, session
):
    """XSS armazenado: mesmo que um valor perigoso já esteja no banco (dado legado,
    importação, bug de validação), o autoescape do Jinja2 o neutraliza na saída."""
    payload_reason = '<script>alert("xss")</script>'
    payload_name = '"><img src=x onerror=alert(1)>'
    recep, appt = _seed_agenda(make_user, make_patient, make_appointment, session, payload_name, payload_reason)

    assert web_login(client, recep.email).status_code == 303
    day = appt.date_time.date().isoformat()
    page = client.get(f"/web/agenda?day={day}")
    assert page.status_code == 200
    assert "<script>alert" not in page.text
    assert "<img src=x" not in page.text
    assert "&lt;script&gt;" in page.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page.text


def test_pagina_agenda_nao_expoe_dados_confidenciais(client, make_user, make_patient, make_appointment, session):
    recep, appt = _seed_agenda(make_user, make_patient, make_appointment, session, "Joana Prado", "Retorno")
    web_login(client, recep.email)
    page = client.get(f"/web/agenda?day={appt.date_time.date().isoformat()}")
    assert "Joana Prado" in page.text and "Dra Helena" in page.text
    assert "SEGREDO-CLINICO-123" not in page.text  # anotações clínicas
    assert "11988887777" not in page.text  # telefone
    assert "***" not in page.text and "cpf" not in page.text.lower()


def test_parametro_de_data_nao_e_refletido(client, make_user):
    recep = make_user(Role.recepcionista)
    web_login(client, recep.email)
    r = client.get("/web/agenda?day=<script>alert(1)</script>")
    assert r.status_code == 422
    assert "<script>alert(1)" not in r.text


def test_cookie_de_sessao_httponly_samesite_strict(client, make_user):
    recep = make_user(Role.recepcionista)
    r = web_login(client, recep.email)
    cookie = next(v for k, v in r.headers.multi_items() if k == "set-cookie" and "clinica_session" in v)
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Samesite", "SameSite").replace("samesite", "SameSite")


def test_login_web_sem_csrf_e_negado(client, make_user):
    recep = make_user(Role.recepcionista)
    r = client.post("/web/login", data={"username": recep.email, "password": "x", "csrf_token": "falso"})
    assert r.status_code == 403


def test_templates_usam_heranca_e_nunca_desligam_autoescape():
    tpl = Path(__file__).resolve().parent.parent / "templates"
    base = (tpl / "base.html").read_text()
    assert "{% block content %}" in base
    for name in ("login.html", "agenda.html"):
        assert '{% extends "base.html" %}' in (tpl / name).read_text()
    for file in tpl.glob("*.html"):
        text = re.sub(r"\{#.*?#\}", "", file.read_text(), flags=re.S)  # ignora comentários Jinja
        assert "|safe" not in text and "| safe" not in text, file.name
        assert "autoescape false" not in text, file.name

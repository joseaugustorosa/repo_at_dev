"""Exercício 1 — primeiro arquivo de testes: caminho de sucesso do recurso `consultas`."""
from tests.helpers import next_slot
from models.users import Role


def test_home_ok(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "message" in r.json()


def test_profissional_cria_e_lista_consulta_do_proprio_paciente(client, make_user, make_patient, auth):
    doctor = make_user(Role.profissional)
    patient = make_patient(doctor)
    headers = auth(doctor)

    payload = {
        "patient_id": patient.id,
        "date_time": next_slot().isoformat(timespec="seconds"),
        "reason": "Retorno de exames",
        "notes": "Paciente estável.",
    }
    created = client.post("/appointment/new", json=payload, headers=headers)
    assert created.status_code == 201
    body = created.json()
    assert body["patient_id"] == patient.id
    assert body["professional_id"] == doctor.id  # veio do token, não do corpo
    assert body["status"] == "agendada"

    listed = client.get("/appointment/", headers=headers)
    assert listed.status_code == 200
    assert [a["id"] for a in listed.json()] == [body["id"]]

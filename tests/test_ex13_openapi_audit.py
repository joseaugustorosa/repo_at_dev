"""Exercício 13 — a auditoria da especificação OpenAPI roda como teste: contrato inseguro quebra o CI."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from audit_openapi import audit, load_spec  # noqa: E402


def test_openapi_sem_nenhum_fail():
    results = audit(load_spec())
    fails = [(cid, msg) for cid, level, msg in results if level == "FAIL"]
    assert not fails, fails
    assert len(results) >= 12


def test_auditoria_detecta_endpoint_publico_esquecido():
    """Prova que o check O-01 funciona: uma operação sem `security` fora da allowlist reprova."""
    spec = load_spec()
    spec["paths"]["/novo-endpoint"] = {"get": {"operationId": "novo", "tags": ["x"], "responses": {"200": {"description": "ok"}}}}
    results = {cid: level for cid, level, _ in audit(spec)}
    assert results["O-01"] == "FAIL"


def test_auditoria_detecta_corpo_aberto_e_campo_sensivel_em_resposta():
    spec = load_spec()
    spec["components"]["schemas"]["AppointmentCreate"]["additionalProperties"] = True
    spec["components"]["schemas"]["AppointmentPublic"]["properties"]["internal_audit_note"] = {"type": "string"}
    results = {cid: level for cid, level, _ in audit(spec)}
    assert results["O-02"] == "FAIL" and results["O-06"] == "FAIL"

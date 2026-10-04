"""Exercício 12 — a lógica do security gate é testada (um gate que libera por engano é pior que nenhum)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from ci_gate import decide  # noqa: E402


def test_libera_somente_se_todos_os_jobs_passaram():
    ok, _ = decide({"sast": {"result": "success"}, "tests": {"result": "success"}})
    assert ok is True


@pytest.mark.parametrize("bad", ["failure", "cancelled", "skipped"])
def test_qualquer_resultado_diferente_de_success_bloqueia(bad):
    ok, results = decide({"sast": {"result": "success"}, "dast-passive": {"result": bad}})
    assert ok is False and results["dast-passive"] == bad


def test_sem_nenhum_job_bloqueia():
    assert decide({})[0] is False


def test_workflow_referencia_o_script_e_nao_usa_actions_mutaveis():
    wf = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "security-pipeline.yml").read_text()
    assert "scripts/ci_gate.py" in wf
    import re

    for line in wf.splitlines():
        m = re.search(r"uses:\s*([\w./-]+)@(\S+)", line)
        if m:
            assert re.fullmatch(r"[0-9a-f]{40}", m.group(2)), f"Action não fixada por SHA: {line.strip()}"

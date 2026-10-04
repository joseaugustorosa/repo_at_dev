"""A calculadora CVSS (scripts/cvss.py) reproduz scores de referência públicos."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from cvss import FINDINGS, base_score, severity  # noqa: E402


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # XSS refletido clássico
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.2),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_base_score_confere_com_referencias(vector, expected):
    assert base_score(vector) == expected


def test_faixas_de_severidade():
    assert [severity(s) for s in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == [
        "Nenhuma", "Baixa", "Média", "Média", "Alta", "Alta", "Crítica", "Crítica"]


def test_todo_achado_tem_vetor_valido_e_impacto_de_negocio():
    assert len({f.id for f in FINDINGS}) == len(FINDINGS)
    for f in FINDINGS:
        assert 0 < f.score <= 10 and f.impact in (1, 2, 3, 4) and f.priority in {"P0", "P1", "P2", "P3"}


def test_bola_de_leitura_tem_cvss_medio_mas_prioridade_alta_por_impacto_de_negocio():
    bola = next(f for f in FINDINGS if f.id == "F-05")
    assert severity(bola.score) == "Média" and bola.priority == "P1"

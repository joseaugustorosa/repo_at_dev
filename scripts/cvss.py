"""Calculadora CVSS v3.1 (Base Score) + priorização das vulnerabilidades do Assessment (Ex. 12).

Uso:  python scripts/cvss.py            -> imprime a tabela em Markdown
      python scripts/cvss.py --write    -> grava docs/cvss_priorizacao.md
Fórmulas: FIRST CVSS v3.1 Specification, seção 7 (pesos e arredondamento "Roundup").
"""
import math
import sys
from dataclasses import dataclass
from pathlib import Path

W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = dict(part.split(":") for part in vector.removeprefix("CVSS:3.1/").split("/"))
    scope_changed = m["S"] == "C"
    iss = 1 - (1 - W["CIA"][m["C"]]) * (1 - W["CIA"][m["I"]]) * (1 - W["CIA"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * PR[m["S"]][m["PR"]] * W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return roundup(min(total, 10))


def severity(score: float) -> str:
    return ("Nenhuma" if score == 0 else "Baixa" if score < 4 else "Média" if score < 7
            else "Alta" if score < 9 else "Crítica")


IMPACT_LABEL = {4: "Crítico", 3: "Alto", 2: "Médio", 1: "Baixo"}


@dataclass
class Finding:
    id: str
    title: str
    owasp: str
    vector: str
    impact: int  # impacto de negócio 1..4 (critério abaixo)
    why: str  # justificativa do impacto
    fix: str  # correção aplicada
    ex: str  # exercício em que foi tratada

    @property
    def score(self) -> float:
        return base_score(self.vector)

    @property
    def priority(self) -> str:
        s = self.score
        if s >= 9.0 or (s >= 7.0 and self.impact >= 3):
            return "P0"
        if s >= 7.0 or self.impact == 4:
            return "P1"
        return "P2" if s >= 4.0 else "P3"


FINDINGS = [
    Finding("F-01", "Cadastro público aceita `role=admin` (mass assignment)", "A01:2021 / API3:2023",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 4,
            "Qualquer pessoa vira administrador e lê/altera dados de todos os pacientes.",
            "Signup só para admin; `extra='forbid'`; papel validado por Enum", "Ex. 9"),
    Finding("F-02", "Segredo JWT fixo no código/repositório (forja de token)", "A02:2021 / A07:2021",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 4,
            "Token de admin forjado sem credencial; acesso total a dados de saúde.",
            "Segredo via BaseSettings/.env (>= 32 chars); iss/aud/exp/jti obrigatórios; HS256 fixo", "Ex. 6/11"),
    Finding("F-03", "SQL injection na busca de pacientes (query por f-string)", "A03:2021",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 4,
            "Dump/alteração de toda a base de pacientes (CPF, telefone), inclusive de outros profissionais.",
            "`select().where()` parametrizado + whitelist do termo + LIKE com autoescape", "Ex. 9/11"),
    Finding("F-04", "BOLA de escrita: PUT/DELETE de consulta de outro profissional", "A01:2021 / API1:2023",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 4,
            "Adulteração do prontuário e cancelamento de consultas alheias (integridade clínica).",
            "Filtro de ownership dentro da query (auth/ownership.py); 404 uniforme", "Ex. 9"),
    Finding("F-05", "BOLA de leitura: prontuário de outro profissional por ID na URL", "A01:2021 / API1:2023",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 4,
            "Vazamento de dado de saúde de terceiro (LGPD art. 11, notificação à ANPD) — CVSS 'médio', impacto crítico.",
            "Mesmo filtro de ownership; auditoria de tentativa (object_access_denied)", "Ex. 9"),
    Finding("F-06", "BOLA no mesmo padrão em `GET /patient/{id}` (+ CPF completo)", "A01:2021 / API1:2023",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 4,
            "Identificação de pacientes de outro profissional; CPF é identificador forte.",
            "scope_patients() + máscara de CPF no response model", "Ex. 9"),
    Finding("F-07", "Força bruta no login (sem rate limit nem MFA)", "A07:2021",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 3,
            "Tomada de contas de equipe clínica; admin sem 2º fator seria comprometimento total.",
            "5/min por conta + 20/min por IP (429); bcrypt; MFA TOTP obrigatório para admin", "Ex. 6/10"),
    Finding("F-08", "Dependências com CVEs conhecidas (FastAPI/Starlette, python-multipart, python-jose)",
            "A06:2021",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 3,
            "ReDoS em parsing de formulário público derruba o agendamento (disponibilidade).",
            "Versões atualizadas e fixadas; PyJWT no lugar de python-jose; pip-audit no CI", "Ex. 12"),
    Finding("F-09", "XSS armazenado na agenda da recepção", "A03:2021",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 3,
            "Script roda na sessão de quem abre a agenda e pode agir como recepcionista (dados de pacientes).",
            "Whitelist de entrada + autoescape do Jinja2 + CSP sem script + cookie HttpOnly", "Ex. 2/9"),
    Finding("F-10", "Resposta devolve campos internos de auditoria e CPF completo", "API3:2023",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 2,
            "Facilita mapeamento do sistema e identificação de usuários por terceiros.",
            "Response models Pydantic com whitelist de campos", "Ex. 2"),
    Finding("F-11", "CORS com curinga e ausência de cabeçalhos de segurança", "A05:2021",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 2,
            "Reprovação em auditoria de pré-produção; leitura cross-origin por site malicioso.",
            "Allowlist de origens; HSTS, X-Frame-Options, X-Content-Type-Options, CSP", "Ex. 10"),
]


def table() -> str:
    rows = sorted(FINDINGS, key=lambda f: (-f.impact, -f.score))
    out = ["| Prio | ID | Vulnerabilidade | OWASP | Vetor CVSS 3.1 | Score | Severidade | Impacto de negócio | Correção | Ex. |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for f in rows:
        out.append(f"| **{f.priority}** | {f.id} | {f.title} | {f.owasp} | `{f.vector.removeprefix('CVSS:3.1/')}` | "
                   f"**{f.score:.1f}** | {severity(f.score)} | {IMPACT_LABEL[f.impact]} — {f.why} | {f.fix} | {f.ex} |")
    return "\n".join(out)


HEADER = """# Priorização das vulnerabilidades — CVSS v3.1 + impacto de negócio (Exercício 12)

Scores calculados por `scripts/cvss.py` (fórmulas da especificação FIRST CVSS v3.1); os vetores
são avaliação do autor para a versão **antes** das correções — não são scores oficiais do NVD.

## Critério de impacto de negócio (dados de saúde — LGPD art. 5º II e art. 11)

| Nível | Critério |
|---|---|
| **4 — Crítico** | Exposição, alteração ou controle de dados de saúde de **vários pacientes/terceiros** ou de contas administrativas; exige notificação à ANPD/titulares (LGPD art. 48) e pode paralisar a clínica. |
| **3 — Alto** | Compromete sessão/conta de equipe clínica ou a disponibilidade do agendamento; dado de saúde só alcançável com passos adicionais. |
| **2 — Médio** | Facilita ataques ou reprova em auditoria, sem acesso direto a dado de saúde. |
| **1 — Baixo** | Informação técnica sem efeito direto. |

## Regra de prioridade

* **P0** — CVSS ≥ 9,0, **ou** CVSS ≥ 7,0 com impacto ≥ 3 → corrige antes de qualquer release;
* **P1** — CVSS ≥ 7,0, **ou** impacto = 4 (mesmo com CVSS < 7: ex. BOLA de leitura, CVSS 6,5 mas dado de saúde de terceiro);
* **P2** — CVSS 4,0–6,9 · **P3** — CVSS < 4,0.

O CVSS mede gravidade técnica; **não enxerga** o que significa vazar um prontuário. Por isso o impacto de
negócio entra na regra, e por isso as falhas de autorização têm testes que bloqueiam o pipeline *independentemente* de score.

## Tabela (ordenada por impacto de negócio e score)

"""


if __name__ == "__main__":
    content = HEADER + table() + "\n"
    if "--write" in sys.argv:
        target = Path(__file__).resolve().parent.parent / "docs" / "cvss_priorizacao.md"
        target.write_text(content)
        print(f"gravado: {target}")
    else:
        print(content)

"""Gera a matriz ameaça -> teste -> resultado (Exercício 13) a partir de tests/threat_matrix.py.

Executa cada teste citado com pytest e registra PASS/FAIL real.
Uso: python scripts/gen_traceability.py   -> grava docs/matriz_ameaca_teste.md
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.threat_matrix import THREATS  # noqa: E402


def node_id(ref: str) -> str:
    module, *path = ref.split("::")
    return "::".join([f"tests/{module}.py", *path])


def run(ref: str) -> str:
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider",
                           node_id(ref)], cwd=ROOT, capture_output=True, text=True)
    return "PASS" if proc.returncode == 0 else "FAIL"


lines = ["# Matriz de rastreabilidade: ameaça (Ex. 4) → teste automatizado (Ex. 12/13)", "",
         "Gerada por `python scripts/gen_traceability.py`; cada teste foi executado e o resultado é real.", "",
         "| ID | Ameaça | Teste(s) que a cobrem | Resultado |", "|---|---|---|---|"]
total = failed = 0
for tid, (desc, refs) in THREATS.items():
    results = {ref: run(ref) for ref in refs}
    total += len(refs)
    failed += sum(r == "FAIL" for r in results.values())
    tests = "<br>".join(f"`{r.replace('::', ' › ')}`" for r in refs)
    status = "<br>".join(("✅" if v == "PASS" else "❌") for v in results.values())
    lines.append(f"| {tid} | {desc} | {tests} | {status} |")
lines += ["", f"**{total - failed}/{total} verificações de teste passaram** ({len(THREATS)} ameaças mapeadas)."]
(ROOT / "docs" / "matriz_ameaca_teste.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines[-1:]))
sys.exit(1 if failed else 0)

"""Decisão final do SECURITY GATE (job `security-gate` do workflow).

Recebe em $RESULTS o JSON `toJSON(needs)` do GitHub Actions e libera SOMENTE se todos os
jobs obrigatórios terminaram com `success`. `skipped`, `cancelled` e `failure` bloqueiam:
um job pulado por engano não pode liberar o merge.
"""
import json
import os
import sys


def decide(needs: dict) -> tuple[bool, dict[str, str]]:
    results = {name: info.get("result", "missing") for name, info in needs.items()}
    return all(r == "success" for r in results.values()) and bool(results), results


if __name__ == "__main__":
    ok, results = decide(json.loads(os.environ["RESULTS"]))
    for name, result in results.items():
        print(f"{name:<18} {result}")
    print("SECURITY GATE: LIBERADO" if ok else "SECURITY GATE: BLOQUEADO")
    sys.exit(0 if ok else 1)

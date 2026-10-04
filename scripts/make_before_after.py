"""Monta a tabela visual ANTES x DEPOIS (Exercício 9) a partir dos JSONs gerados por attack.py."""
import json
from html import escape
from pathlib import Path

D = Path(__file__).resolve().parent.parent / "evidence" / "ex08_ex09_antes_depois"
before = {r["id"]: r for r in json.loads((D / "resultado_antes.json").read_text())["results"]}
after = {r["id"]: r for r in json.loads((D / "resultado_depois.json").read_text())["results"]}

rows = []
for aid in sorted(before, key=lambda x: int(x[1:])):
    b, a = before[aid], after[aid]
    rows.append(f"<tr><td><b>{aid}</b></td><td>{escape(b['owasp'])}<br><small>{escape(b['title'])}</small></td>"
                f"<td class='{'bad' if b['verdict']=='EXPLORADO' else 'ok'}'>{b['verdict']}</td>"
                f"<td class='{'bad' if a['verdict']=='EXPLORADO' else 'ok'}'>{a['verdict']}</td>"
                f"<td><small>{escape(a['evidence'][:150])}</small></td></tr>")
nb = sum(r["verdict"] == "EXPLORADO" for r in before.values())
na = sum(r["verdict"] == "EXPLORADO" for r in after.values())
html = f"""<!doctype html><meta charset=utf-8><style>
body{{font:14px/1.4 -apple-system,Segoe UI,Helvetica,sans-serif;margin:24px;color:#1b2430}} h2{{margin:0 0 4px}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #d5dbe3;padding:7px 9px;vertical-align:top;text-align:left}}
th{{background:#eef2f6}} .bad{{background:#fde8e8;color:#b42318;font-weight:700;text-align:center}}
.ok{{background:#e6f4ea;color:#1e6b3a;font-weight:700;text-align:center}} small{{color:#4a5666}}</style>
<h2>Exercício 9 — o mesmo ataque, antes e depois da correção</h2>
<p>Mesmo conjunto de 10 requisições (<code>attack.py</code>) contra a versão vulnerável (:8001) e a corrigida (:8000).
<b>Antes: {nb}/10 explorados · Depois: {na}/10 explorados.</b></p>
<table><tr><th>ID</th><th>Categoria OWASP / ataque</th><th>ANTES</th><th>DEPOIS</th><th>Evidência (versão corrigida)</th></tr>{''.join(rows)}</table>"""
(D / "antes_depois.html").write_text(html)
print(f"antes: {nb} explorados | depois: {na} explorados")

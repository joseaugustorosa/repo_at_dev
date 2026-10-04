"""Monta RELATORIO_TECNICO.pdf a partir de RELATORIO_TECNICO.md (+ anexos incluídos) usando o Chrome headless.

Uso: python scripts/build_report.py
- Substitui marcadores `<!-- include: caminho.md -->` pelo conteúdo do arquivo (rebaixando os títulos).
- Gera HTML em .build/ (com <base> apontando para a raiz, para as imagens relativas funcionarem) e imprime em PDF.
Requer: pip install markdown  e  Google Chrome instalado (macOS).
"""
import re
import subprocess
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BUILD = ROOT / ".build"
BUILD.mkdir(exist_ok=True)

CSS = """
@page { size: A4; margin: 16mm 14mm; }
body { font: 10.5pt/1.45 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1b2430; }
h1 { font-size: 20pt; border-bottom: 3px solid #0b6bcb; padding-bottom: 6px; }
h2 { font-size: 15pt; margin-top: 26px; border-bottom: 1px solid #c9d1db; padding-bottom: 3px; page-break-after: avoid; }
h3 { font-size: 12pt; margin-top: 18px; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 14px; font-size: 8.8pt; page-break-inside: auto; }
tr { page-break-inside: avoid; }
th, td { border: 1px solid #cfd6df; padding: 4px 6px; vertical-align: top; text-align: left; }
th { background: #eef2f6; }
code { font: 8.8pt "SF Mono", Menlo, Consolas, monospace; background: #f1f4f8; padding: 1px 3px; border-radius: 3px; }
pre { background: #f6f8fa; border: 1px solid #dde3ea; border-radius: 6px; padding: 8px 10px; overflow: hidden; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8pt; white-space: pre-wrap; }
blockquote { margin: 10px 0; padding: 6px 12px; border-left: 4px solid #d68910; background: #fff8e6; }
img { max-width: 100%; page-break-inside: avoid; }
a { color: #0b6bcb; text-decoration: none; }
"""


def blank_line_before_lists(text: str) -> str:
    """python-markdown só reconhece lista se houver linha em branco antes; o texto-fonte nem sempre tem."""
    out, in_fence = [], False
    list_item = re.compile(r"^(\s*)([*-]|\d+\.) ")
    for line in text.split("\n"):
        if line.startswith("```"):
            in_fence = not in_fence
        if (not in_fence and out and list_item.match(line) and out[-1].strip()
                and not list_item.match(out[-1]) and not out[-1].startswith(("|", "    ", "<"))):
            out.append("")
        out.append(line)
    return "\n".join(out)


def include(match: re.Match) -> str:
    target = ROOT / match.group(1).strip()
    text = target.read_text()
    text = re.sub(r"\A# .*\n", "", text)  # remove o H1 do anexo (o relatório já tem o título do anexo)
    return re.sub(r"^(#{2,5}) ", lambda m: "#" * (len(m.group(1)) + 1) + " ", text, flags=re.M)


def include_code(match: re.Match) -> str:
    return "```text\n" + (ROOT / match.group(1).strip()).read_text().rstrip() + "\n```"


def main() -> int:
    source = (ROOT / "RELATORIO_TECNICO.md").read_text()
    source = re.sub(r"<!--\s*include-code:\s*(.+?)\s*-->", include_code, source)
    source = re.sub(r"<!--\s*include:\s*(.+?)\s*-->", include, source)
    source = blank_line_before_lists(source)
    body = markdown.markdown(source, extensions=["tables", "fenced_code", "sane_lists"])
    html = f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><base href="file://{ROOT}/">
<title>Relatório Técnico — API de Agendamento Clínico</title><style>{CSS}</style></head><body>{body}</body></html>"""
    page = BUILD / "relatorio.html"
    page.write_text(html)
    pdf = ROOT / "RELATORIO_TECNICO.pdf"
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf}",
                    f"file://{page}"], check=True, capture_output=True, timeout=180)
    print(f"gerado: {pdf} ({pdf.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

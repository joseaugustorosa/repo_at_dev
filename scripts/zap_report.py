"""Gate e relatório de correlação para o scan do OWASP ZAP (Exercícios 12 e 13).

  python scripts/zap_report.py gate   report_json.json [rules.tsv]
      -> sai com 1 se houver alerta que BLOQUEIA: regra marcada FAIL em .zap/rules.tsv, OU risco >= Médio
         (riskcode do ZAP 2 ou 3) que não esteja marcado IGNORE. (Por que não `fail_action: true` da Action:
         ela falha em QUALQUER alerta, inclusive informativo, e ignora a distinção FAIL/WARN.)
  python scripts/zap_report.py report a.json[,b.json,...] [saida.md] [--logs log_a.txt[,log_b.txt,...]]
      -> tabela: alerta do ZAP -> CWE -> categoria OWASP -> controle no código -> teste -> status,
         e a lista de regras do ZAP cujo SILÊNCIO comprova um controle. O silêncio só vale como
         prova quando a regra aparece como `PASS` no log do scan (regra que nem rodou não prova nada).

Entrada: o `report_json.json` gerado pelo ZAP (zap-baseline.py / zap-api-scan.py -J).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RISK = {0: "Informativo", 1: "Baixo", 2: "Médio", 3: "Alto"}

# regra do ZAP -> (categoria OWASP Top 10 2021, controle implementado, teste que o cobre)
CONTROLS: dict[str, tuple[str, str, str]] = {
    "10020": ("A05:2021 Security Misconfiguration", "X-Frame-Options: DENY + CSP frame-ancestors — core/security_headers.py", "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"),
    "10021": ("A05:2021 Security Misconfiguration", "X-Content-Type-Options: nosniff — core/security_headers.py", "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"),
    "10035": ("A05:2021 Security Misconfiguration", "Strict-Transport-Security — core/security_headers.py", "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"),
    "10038": ("A05:2021 Security Misconfiguration", "Content-Security-Policy restritiva — core/security_headers.py", "test_ex10_hardening::test_csp_da_api_e_restritiva_e_a_da_docs_permite_apenas_o_necessario"),
    "10098": ("A05:2021 Security Misconfiguration", "CORS com allowlist explícita — main.py / core/config.py", "test_ex10_hardening::test_origem_nao_listada_nao_recebe_cors"),
    "10010": ("A05:2021 Security Misconfiguration", "Cookie de sessão HttpOnly — routes/web.py", "test_ex02_response_models_xss::test_cookie_de_sessao_httponly_samesite_strict"),
    "10011": ("A02:2021 Cryptographic Failures", "Cookie Secure (obrigatório em produção) — core/config.py", "test_ex11_persistence::test_producao_exige_endurecimento"),
    "10054": ("A01:2021 Broken Access Control", "Cookie SameSite=Strict — routes/web.py", "test_ex02_response_models_xss::test_cookie_de_sessao_httponly_samesite_strict"),
    "10202": ("A01:2021 Broken Access Control", "Token CSRF (double-submit) — core/csrf.py", "test_ex12_threat_vectors::test_logout_exige_csrf"),
    "10036": ("A05:2021 Security Misconfiguration", "uvicorn --no-server-header", "(configuração de execução — README)"),
    "10037": ("A05:2021 Security Misconfiguration", "Sem X-Powered-By", "—"),
    "90022": ("A05:2021 Security Misconfiguration", "Handler de erros sem eco do input / sem stack trace — main.py", "test_ex09_input_validation::test_erro_de_validacao_nao_ecoa_o_valor_enviado"),
    "10015": ("A05:2021 Security Misconfiguration", "Cache-Control: no-store em respostas com dados de saúde", "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"),
    "10063": ("A05:2021 Security Misconfiguration", "Permissions-Policy — core/security_headers.py", "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas"),
    "90004": ("A05:2021 Security Misconfiguration", "COOP + COEP + CORP (isolamento de site) — core/security_headers.py", "test_ex10_hardening::test_coep_presente_nas_respostas_e_ausente_na_documentacao"),
}
# Alertas INFORMATIVOS esperados, aceitos com justificativa (regra -> motivo)
ACCEPTED: dict[str, tuple[str, str, str, str]] = {
    # regra -> (OWASP, controle, teste, justificativa da aceitação)
    "10049": ("A05:2021 Security Misconfiguration", "`Cache-Control: no-store` em respostas com dado de saúde — core/security_headers.py",
              "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas",
              "é o EFEITO do `no-store` imposto de propósito (proxies/navegadores não devem armazenar dado de paciente) — confirma o controle de T-I3"),
    "10111": ("A07:2021 Identification and Authentication Failures", "login protegido por rate limit, bcrypt e MFA — routes/users.py",
              "test_ex10_hardening::test_login_e_limitado_a_5_tentativas_por_janela",
              "apenas registra a existência de `POST /user/signin`, endpoint que deve existir"),
    "10049s": ("A05:2021 Security Misconfiguration", "`/static/` (CSS público, sem dado de saúde) é cacheável de propósito — main.py / core/security_headers.py",
               "test_ex10_hardening::test_cabecalhos_obrigatorios_em_todas_as_respostas",
               "só o CSS público é armazenável; nenhuma resposta com dado de paciente é (essas têm `no-store`)"),
    "10112": ("A07:2021 Identification and Authentication Failures", "cookie `csrf_token` HttpOnly + SameSite=Strict + Secure — core/csrf.py",
              "test_ex02_response_models_xss::test_login_web_sem_csrf_e_negado",
              "o ZAP apenas identifica o cookie do token CSRF como identificador de sessão; é o controle, não uma falha"),
    "100000": ("A01:2021 Broken Access Control", "RBAC, ownership, validação `extra='forbid'` — auth/rbac.py, auth/ownership.py",
               "test_ex06_authz / test_ex09_input_validation",
               "4xx é o comportamento desejado: 403 = RBAC negando o perfil (T-E2); 422 = validação (T-T1/T-T2); 404 = ownership/inexistente (T-I2); 400 = invalid_scope (T-T4)"),
}
# CWE -> categoria OWASP (usado quando a regra não está em CONTROLS)
CWE_TO_OWASP = {
    "79": "A03:2021 Injection (XSS)", "89": "A03:2021 Injection (SQL)", "352": "A01:2021 Broken Access Control",
    "639": "A01:2021 Broken Access Control", "284": "A01:2021 Broken Access Control",
    "200": "A01:2021 Broken Access Control / A05", "209": "A05:2021 Security Misconfiguration",
    "693": "A05:2021 Security Misconfiguration", "1021": "A05:2021 Security Misconfiguration",
    "16": "A05:2021 Security Misconfiguration", "319": "A02:2021 Cryptographic Failures",
    "614": "A02:2021 Cryptographic Failures", "1004": "A05:2021 Security Misconfiguration",
    "1275": "A01:2021 Broken Access Control", "523": "A02:2021 Cryptographic Failures",
    "521": "A07:2021 Identification and Authentication Failures", "1104": "A06:2021 Vulnerable Components",
}


def load_alerts(path: Path) -> list[dict]:
    data = json.loads(Path(path).read_text())
    return [a for site in data.get("site", []) for a in site.get("alerts", [])]


def load_rules(path: Path | None) -> dict[str, str]:
    rules: dict[str, str] = {}
    if path and Path(path).exists():
        for line in Path(path).read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    rules[parts[0].strip()] = parts[1].strip().upper()
    return rules


def blocking(alerts: list[dict], rules: dict[str, str]) -> list[dict]:
    out = []
    for a in alerts:
        action = rules.get(str(a.get("pluginid")), "")
        if action == "IGNORE":
            continue
        if action == "FAIL" or int(a.get("riskcode", 0)) >= 2:
            out.append(a)
    return out


def instances(a: dict) -> int:
    return int(a.get("count") or len(a.get("instances", [])) or 0)


def cmd_gate(report: Path, rules_path: Path | None) -> int:
    alerts = load_alerts(report)
    rules = load_rules(rules_path)
    bad = blocking(alerts, rules)
    print(f"{len(alerts)} alerta(s) no relatório; {len(bad)} bloqueante(s).")
    for a in bad:
        print(f"  [{RISK[int(a['riskcode'])]}] {a.get('pluginid')} {a.get('name') or a.get('alert')}"
              f" — {instances(a)} ocorrência(s), CWE-{a.get('cweid')}")
    print("ZAP GATE: BLOQUEADO" if bad else "ZAP GATE: LIBERADO")
    return 1 if bad else 0


def alert_key(a: dict) -> str:
    """ID da regra; a regra 10049 emite dois alertas distintos (Non-Storable × Storable and Cacheable)."""
    pid = str(a.get("pluginid"))
    return "10049s" if pid == "10049" and str(a.get("name", "")).startswith("Storable") else pid


def passed_rules(logs: list[Path]) -> set[str]:
    """IDs das regras que rodaram e NÃO geraram alerta (linhas `PASS: nome [id]` do console do ZAP)."""
    ids: set[str] = set()
    for log in logs:
        ids |= set(re.findall(r"^PASS: .*\[(\d+)\]\s*$", Path(log).read_text(), flags=re.M))
    return ids


def cmd_report(reports: list[Path], out: Path | None, logs: list[Path] | None = None) -> int:
    merged: dict[str, dict] = {}
    for report in reports:
        for a in load_alerts(report):
            pid = alert_key(a)
            entry = merged.setdefault(pid, {**a, "_scans": [], "_count": 0})
            entry["_scans"].append(Path(report).stem)
            entry["_count"] += instances(a)
    ran = passed_rules(logs or [])
    rows = ["| Regra ZAP | Alerta | Risco | CWE | Ocorr. | Encontrado em | OWASP Top 10 | Controle no código | Teste | Status |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for pid, a in sorted(merged.items(), key=lambda kv: -int(kv[1].get("riskcode", 0))):
        owasp, control, test = CONTROLS.get(pid, (CWE_TO_OWASP.get(str(a.get("cweid")), "a classificar"), "—", "—"))
        accepted = ACCEPTED.get(pid)
        if accepted:
            owasp, control, test, why = accepted
            status = f"✅ **aceito** — {why}"
        elif pid in CONTROLS:
            status = "⚠️ **revisar** — o controle existe, mas o ZAP o viu falhar em alguma URL"
        else:
            status = "🔎 **finding novo** — classificar, corrigir ou aceitar com justificativa"
        rows.append(f"| {pid} | {a.get('name') or a.get('alert')} | {RISK[int(a['riskcode'])]} | {a.get('cweid')} | "
                    f"{a['_count']} | {', '.join(sorted(set(a['_scans'])))} | {owasp} | {control} | `{test}` | {status} |")
    if not merged:
        rows.append("| — | *nenhum alerta* | | | | | | | | ✅ |")
    silent = ["", "## Controles comprovados pelo silêncio do ZAP", ""]
    if ran:
        silent += ["Regras que **rodaram** (`PASS` no log do scan) e **não** geraram alerta — a ausência é a evidência de que o controle funciona nas URLs varridas.", "",
                   "| Regra ZAP | OWASP | Controle verificado |", "|---|---|---|"]
        for pid, (owasp, control, _) in CONTROLS.items():
            if pid in ran and pid not in merged:
                silent.append(f"| {pid} | {owasp} | {control} |")
        not_run = [pid for pid in CONTROLS if pid not in ran and pid not in merged]
        if not_run:
            silent += ["", f"*Não verificadas por este scan (a regra não consta como PASS no log): {', '.join(not_run)}.*"]
    else:
        silent.append("*Sem o log do scan (`--logs`), não é possível distinguir 'regra executada sem alerta' de 'regra não executada'; nada é afirmado.*")
    text = "# Correlação: findings do ZAP → OWASP → correção → teste\n\n" + "\n".join(rows) + "\n" + "\n".join(silent) + "\n"
    if out:
        Path(out).write_text(text)
        print(f"gravado: {out}")
    else:
        print(text)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in {"gate", "report"}:
        print(__doc__)
        return 2
    logs: list[Path] = []
    if "--logs" in argv:
        i = argv.index("--logs")
        logs = [Path(p) for p in argv[i + 1].split(",")]
        argv = argv[:i] + argv[i + 2:]
    reports = [Path(p) for p in argv[2].split(",")]
    for r in reports:
        if not r.exists():
            print(f"arquivo não encontrado: {r}", file=sys.stderr)
            return 2
    if argv[1] == "gate":
        rules = Path(argv[3]) if len(argv) > 3 else ROOT / ".zap" / "rules.tsv"
        return max(cmd_gate(r, rules) for r in reports)
    return cmd_report(reports, Path(argv[3]) if len(argv) > 3 else None, logs)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

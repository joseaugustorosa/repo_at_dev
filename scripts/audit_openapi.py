"""Auditoria da especificação OpenAPI (Exercício 13).

Verifica, na spec GERADA pela aplicação, propriedades de segurança do CONTRATO:
autenticação declarada, corpos fechados (extra=forbid), limites de tamanho, campos
sensíveis ausentes das respostas, erros documentados e esquemas de segurança.

Uso:  python scripts/audit_openapi.py [--write]   (grava docs/ex13_openapi_audit.md e evidence/ex13/openapi.json)
Níveis: FAIL (bloqueia o CI) · WARN (achado a tratar/aceitar) · INFO (observação) · PASS
"""
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PUBLIC_OPERATIONS = {
    ("get", "/"), ("get", "/health"),
    ("post", "/user/signin"), ("post", "/user/mfa/verify"), ("post", "/oauth/token"),
}
FORBIDDEN_IN_RESPONSES = {
    "password", "password_hash", "mfa_seed", "mfa_last_step", "mfa_secret",
    "created_by_user_id", "created_at", "updated_at", "created_from_ip", "internal_audit_note",
}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def audit(spec: dict) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    add = lambda cid, level, msg: out.append((cid, level, msg))  # noqa: E731
    schemas = spec.get("components", {}).get("schemas", {})
    ops = [(m, p, o) for p, item in spec["paths"].items() for m, o in item.items() if m in HTTP_METHODS]

    # O-01 autenticação declarada
    public_seen, unprotected = set(), []
    for m, p, o in ops:
        if not o.get("security"):
            public_seen.add((m, p))
            if (m, p) not in PUBLIC_OPERATIONS:
                unprotected.append(f"{m.upper()} {p}")
    extra_public = public_seen - PUBLIC_OPERATIONS
    add("O-01", "FAIL" if extra_public else "PASS",
        f"operações sem `security` além da allowlist: {sorted(unprotected)}" if extra_public else
        f"{len(ops) - len(public_seen)} de {len(ops)} operações exigem autenticação; públicas = {sorted(f'{m.upper()} {p}' for m, p in public_seen)}")

    # O-02 / O-03 corpos JSON fechados e strings limitadas
    open_bodies, loose_strings = [], []
    for m, p, o in ops:
        ref = o.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {}).get("$ref")
        if not ref:
            continue
        sch = schemas[ref.split("/")[-1]]
        if sch.get("additionalProperties") is not False:
            open_bodies.append(f"{m.upper()} {p} ({ref.split('/')[-1]})")
        for name, prop in sch.get("properties", {}).items():
            variants = prop.get("anyOf", [prop])
            for v in variants:
                if v.get("type") == "string" and not any(k in v for k in ("maxLength", "pattern", "enum", "format")):
                    loose_strings.append(f"{ref.split('/')[-1]}.{name}")
    add("O-02", "FAIL" if open_bodies else "PASS",
        f"corpos que aceitam campos extras: {open_bodies}" if open_bodies else "todos os corpos JSON declaram `additionalProperties: false` (extra='forbid')")
    add("O-03", "FAIL" if loose_strings else "PASS",
        f"strings sem limite (maxLength/pattern/enum/format): {loose_strings}" if loose_strings else "toda string de entrada JSON tem pattern, maxLength, enum ou format")

    # O-04 parâmetros numéricos limitados
    unbounded = []
    for m, p, o in ops:
        for prm in o.get("parameters", []):
            sch = prm.get("schema", {})
            variants = sch.get("anyOf", [sch])
            for v in variants:
                if v.get("type") == "integer":
                    bounded = any(k in v for k in ("minimum", "exclusiveMinimum"))
                    if prm["name"] == "limit":
                        bounded = bounded and "maximum" in v
                    if not bounded:
                        unbounded.append(f"{m.upper()} {p} ?{prm['name']}")
    add("O-04", "FAIL" if unbounded else "PASS",
        f"inteiros sem limites: {unbounded}" if unbounded else "IDs têm mínimo (>0) e `limit` tem máximo (paginação limitada)")

    # O-05 respostas tipadas
    untyped = []
    for m, p, o in ops:
        for code, resp in o.get("responses", {}).items():
            if code.startswith("2") and code != "204":
                sch = resp.get("content", {}).get("application/json", {}).get("schema", {})
                if sch in ({}, {"type": "object"}, {"type": "object", "additionalProperties": True}):
                    untyped.append(f"{m.upper()} {p} -> {code}")
    add("O-05", "WARN" if untyped else "PASS",
        f"respostas de sucesso sem schema nomeado: {untyped}" if untyped else "todas as respostas 2xx têm schema definido (response_model)")

    # O-06 campos proibidos nas respostas
    def props_of(name: str, seen=None) -> set[str]:
        seen = seen or set()
        if name in seen:
            return set()
        seen.add(name)
        sch = schemas.get(name, {})
        found = set(sch.get("properties", {}))
        for prop in sch.get("properties", {}).values():
            for node in [prop, prop.get("items", {}), *prop.get("anyOf", [])]:
                if "$ref" in node:
                    found |= props_of(node["$ref"].split("/")[-1], seen)
        return found

    leaks = []
    for m, p, o in ops:
        for code, resp in o.get("responses", {}).items():
            sch = resp.get("content", {}).get("application/json", {}).get("schema", {})
            ref = sch.get("$ref") or sch.get("items", {}).get("$ref")
            if ref and code.startswith("2"):
                bad = props_of(ref.split("/")[-1]) & FORBIDDEN_IN_RESPONSES
                if bad:
                    leaks.append(f"{m.upper()} {p}: {sorted(bad)}")
    add("O-06", "FAIL" if leaks else "PASS",
        f"campos sensíveis/internos em respostas: {leaks}" if leaks else "nenhum campo interno (hash, semente MFA, auditoria) aparece em schema de resposta")

    # O-07 erros documentados em operações protegidas
    missing = [f"{m.upper()} {p}" for m, p, o in ops
               if o.get("security") and not {"401", "429"} <= set(o.get("responses", {}))]
    add("O-07", "WARN" if missing else "PASS",
        f"operações protegidas sem 401/429 documentados: {missing}" if missing else "operações protegidas documentam 401 e 429 (e 403/404 onde aplicável)")

    # O-08 esquemas de segurança
    sec = spec.get("components", {}).get("securitySchemes", {})
    flows = {k: v for s in sec.values() for k, v in s.get("flows", {}).items()}
    api_key_in_url = [n for n, s in sec.items() if s.get("type") == "apiKey" and s.get("in") == "query"]
    ok = "password" in flows and "clientCredentials" in flows and not api_key_in_url
    scopes = flows.get("clientCredentials", {}).get("scopes", {})
    add("O-08", "PASS" if ok else "FAIL",
        f"esquemas: {sorted(sec)}; fluxos: {sorted(flows)}; escopos M2M: {sorted(scopes)}; credencial em query string: {bool(api_key_in_url)}")

    # O-09 servidores
    servers = [s["url"] for s in spec.get("servers", [])]
    insecure = [u for u in servers if u.startswith("http://") and "localhost" not in u]
    add("O-09", "FAIL" if insecure else "INFO",
        f"servers http:// fora de localhost: {insecure}" if insecure else
        "spec não declara `servers`; em produção publicar apenas https:// (TLS e HSTS no proxy)")

    # O-10 formulários OAuth sem maxLength
    form_loose = []
    for m, p, o in ops:
        content = o.get("requestBody", {}).get("content", {}).get("application/x-www-form-urlencoded", {})
        ref = content.get("schema", {}).get("$ref")
        if ref:
            sch = schemas[ref.split("/")[-1]]
            for name, prop in sch.get("properties", {}).items():
                if prop.get("type") == "string" and "maxLength" not in prop and "enum" not in prop:
                    form_loose.append(f"{p}:{name}")
    add("O-10", "WARN" if form_loose else "PASS",
        f"campos de formulário sem maxLength na spec: {form_loose}. Mitigado em código (corte a 254 chars no username; "
        "bcrypt rejeita >72 bytes; rate limit 5/min) — `OAuth2PasswordRequestForm` do FastAPI não declara limites."
        if form_loose else "campos de formulário limitados")

    # O-11 métodos
    odd = [f"{m.upper()} {p}" for m, p, _ in ops if m in {"trace", "head"} or (m in {"put", "delete", "patch"} and "{" not in p)]
    add("O-11", "FAIL" if odd else "PASS",
        f"métodos suspeitos: {odd}" if odd else "PUT/PATCH/DELETE existem apenas sobre recurso identificado; sem TRACE")

    # O-12 operationId único e documentação mínima
    ids = [o.get("operationId") for _, _, o in ops]
    undocumented = [f"{m.upper()} {p}" for m, p, o in ops if not o.get("tags")]
    add("O-12", "FAIL" if len(ids) != len(set(ids)) or undocumented else "PASS",
        "operationId duplicado ou operação sem tag" if len(ids) != len(set(ids)) or undocumented else "operationIds únicos e todas as operações com tag")
    return out


def load_spec() -> dict:
    os.environ.setdefault("DATABASE_URL", "sqlite://")
    os.environ.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(48))
    os.environ.setdefault("MFA_MASTER_KEY", secrets.token_urlsafe(48))
    os.environ.setdefault("ENABLE_DOCS", "true")
    from main import app

    return app.openapi()


def to_markdown(results: list[tuple[str, str, str]], spec: dict) -> str:
    icons = {"PASS": "✅ PASS", "INFO": "ℹ️ INFO", "WARN": "⚠️ WARN", "FAIL": "❌ FAIL"}
    lines = ["# Auditoria da especificação OpenAPI (Exercício 13)", "",
             f"Spec: `{spec['info']['title']}` v{spec['info']['version']} · OpenAPI {spec['openapi']} · "
             f"{sum(len(v) for v in spec['paths'].values())} operações em {len(spec['paths'])} caminhos.",
             "Gerado por `python scripts/audit_openapi.py --write`.", "",
             "| Check | Resultado | Observação |", "|---|---|---|"]
    lines += [f"| {cid} | {icons[level]} | {msg} |" for cid, level, msg in results]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    spec = load_spec()
    results = audit(spec)
    md = to_markdown(results, spec)
    print(md)
    if "--write" in sys.argv:
        (ROOT / "docs" / "ex13_openapi_audit.md").write_text(md)
        out = ROOT / "evidence" / "ex13_capstone"
        out.mkdir(parents=True, exist_ok=True)
        (out / "openapi.json").write_text(json.dumps(spec, indent=2, ensure_ascii=False))
    sys.exit(1 if any(level == "FAIL" for _, level, _ in results) else 0)

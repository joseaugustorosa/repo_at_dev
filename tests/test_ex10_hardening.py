"""Exercício 10 — CORS com allowlist, cabeçalhos de segurança e rate limit de login."""
import pytest
from pydantic import ValidationError

from core.config import Settings
from models.users import Role
from tests.helpers import signin

GOOD_ORIGIN = "http://localhost:3000"
EVIL_ORIGIN = "https://evil.example.org"


# --------------------------------- CORS --------------------------------------
def test_origem_permitida_recebe_cabecalho_cors(client):
    r = client.get("/health", headers={"Origin": GOOD_ORIGIN})
    assert r.headers["access-control-allow-origin"] == GOOD_ORIGIN
    assert "access-control-allow-credentials" not in r.headers


def test_origem_nao_listada_nao_recebe_cors(client):
    r = client.get("/health", headers={"Origin": EVIL_ORIGIN})
    assert "access-control-allow-origin" not in r.headers


def test_preflight_de_origem_nao_listada_e_negado(client):
    r = client.options("/appointment/new", headers={
        "Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers


def test_preflight_permitido_nao_usa_curinga(client):
    r = client.options("/appointment/new", headers={
        "Origin": GOOD_ORIGIN, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == GOOD_ORIGIN
    assert "*" not in r.headers["access-control-allow-origin"]
    assert "*" not in r.headers.get("access-control-allow-headers", "")


@pytest.mark.parametrize("origins", [["*"], ["localhost:3000"], ["http://ok.com", "*"]])
def test_configuracao_recusa_cors_curinga_ou_malformado(origins, monkeypatch):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, cors_allowed_origins=origins)  # type: ignore[call-arg]


# ------------------------- cabeçalhos de segurança ---------------------------
REQUIRED = {
    "strict-transport-security": "max-age=",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
}


@pytest.mark.parametrize("path", ["/", "/health", "/web/login", "/user/me", "/oauth/token"])
def test_cabecalhos_obrigatorios_em_todas_as_respostas(client, path):
    """Inclui respostas de erro (401/405/422): quem manda é o middleware mais externo."""
    r = client.get(path)
    for name, expected in REQUIRED.items():
        assert expected in r.headers[name], f"{name} ausente em {path} ({r.status_code})"
    assert "default-src" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_csp_da_api_e_restritiva_e_a_da_docs_permite_apenas_o_necessario(client):
    api = client.get("/health").headers["content-security-policy"]
    assert "default-src 'none'" in api and "frame-ancestors 'none'" in api and "script-src" not in api
    docs = client.get("/docs").headers["content-security-policy"]
    assert "cdn.jsdelivr.net" in docs and "*" not in docs.replace("'self'", "")


# ------------------------------- rate limit ----------------------------------
def test_login_e_limitado_a_5_tentativas_por_janela(client, make_user):
    user = make_user(Role.recepcionista)
    codes = [signin(client, user.email, "senha-errada-123").status_code for _ in range(5)]
    assert codes == [401] * 5
    blocked = signin(client, user.email, "senha-errada-123")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    # com o limite estourado, até a senha CORRETA é bloqueada (força bruta não "acerta" mais)
    assert signin(client, user.email).status_code == 429


def test_rate_limit_de_login_nao_afeta_outras_rotas(client, make_user, auth):
    user = make_user(Role.recepcionista)
    for _ in range(6):
        signin(client, user.email, "senha-errada-123")
    assert client.get("/health").status_code == 200
    assert client.get("/user/me", headers=auth(user)).status_code == 200


def test_token_endpoint_tambem_tem_limite_estrito(client):
    data = {"grant_type": "client_credentials", "client_id": "laboratorio-parceiro", "client_secret": "errado"}
    codes = [client.post("/oauth/token", data=data).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_coep_presente_nas_respostas_e_ausente_na_documentacao(client):
    """Achado do ZAP (regra 90004): COOP+COEP+CORP completam o isolamento de site (Spectre).
    A documentação (Swagger) carrega scripts de CDN e por isso fica de fora."""
    for path in ("/health", "/web/login", "/user/me"):
        h = client.get(path).headers
        assert h["cross-origin-embedder-policy"] == "require-corp", path
        assert h["cross-origin-opener-policy"] == "same-origin" and h["cross-origin-resource-policy"] == "same-origin"
    assert "cross-origin-embedder-policy" not in client.get("/docs").headers

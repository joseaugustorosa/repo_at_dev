"""Authorization Server mínimo para o fluxo Client Credentials (Exercício 7).

Por que Client Credentials: o laboratório é um *sistema*, não uma pessoa — não
há navegador, nem consentimento de usuário, nem refresh token (RFC 6749 §4.4).
Authorization Code + PKCE (aula 15) é para clientes que agem em nome de uma
pessoa; aqui seria o fluxo errado.

Em produção este papel seria de um IdP (ex.: Keycloak — aula 15 — com um
"service account" para o laboratório). Mantemos um emissor próprio e mínimo
para a entrega ser autocontida; o contrato (grant, escopos, claims) é o mesmo.
"""
import hmac

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from auth.hash_password import HashPassword
from auth.jwt_handler import TokenUse, create_token, m2m_ttl
from core.audit import audit, fingerprint
from core.config import get_settings
from core.rate_limit import enforce_auth_rate_limit

oauth_router = APIRouter(tags=["OAuth2 (laboratório M2M)"])
hasher = HashPassword()


class M2MTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


def _oauth_error(error: str, status_code: int, description: str, **headers: str) -> JSONResponse:
    """Formato de erro do RFC 6749 §5.2."""
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache", **headers},
    )


@oauth_router.post("/token", response_model=M2MTokenResponse, responses={
    400: {"description": "unsupported_grant_type ou invalid_scope (RFC 6749 §5.2)"},
    401: {"description": "invalid_client"},
    429: {"description": "Limite estrito de tentativas excedido"},
})
def issue_token(
    request: Request,
    grant_type: str = Form(..., max_length=40),
    client_id: str = Form(..., max_length=100),
    client_secret: str = Form(..., max_length=200),
    scope: str = Form("", max_length=200),
):
    enforce_auth_rate_limit(request, "token", client_id)
    s = get_settings()

    if grant_type != "client_credentials":
        return _oauth_error("unsupported_grant_type", 400, "Somente client_credentials é suportado.")

    known = bool(s.lab_client_id and s.lab_client_secret_hash) and hmac.compare_digest(
        client_id.encode(), (s.lab_client_id or "").encode()
    )
    if known:
        authenticated = hasher.verify_hash(client_secret, s.lab_client_secret_hash.get_secret_value())
    else:
        hasher.burn_cpu(client_secret)
        authenticated = False
    if not authenticated:
        audit("m2m_token", outcome="failure", client=fingerprint(client_id))
        return _oauth_error("invalid_client", 401, "Autenticação do cliente falhou.",
                            **{"WWW-Authenticate": "Basic"})

    allowed = set(s.lab_allowed_scopes)
    requested = set(scope.split()) or allowed  # sem scope => o máximo permitido ao cliente
    if not requested <= allowed:
        audit("m2m_token", outcome="denied", client=client_id, reason="invalid_scope")
        return _oauth_error("invalid_scope", 400, "Escopo não permitido para este cliente.")

    ttl = m2m_ttl()
    granted = " ".join(sorted(requested))
    token = create_token(
        subject=client_id,
        token_use=TokenUse.m2m,
        ttl=ttl,
        extra_claims={"scope": granted, "client_id": client_id},  # sem claim "role"
    )
    audit("m2m_token", outcome="success", client=client_id, scope=granted)
    return M2MTokenResponse(access_token=token, expires_in=int(ttl.total_seconds()), scope=granted)

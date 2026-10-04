"""Middleware JWT centralizado, *deny-by-default* (Exercício 9).

Toda requisição precisa de um token válido, exceto as rotas da allowlist
`PUBLIC_PATHS`. Isto resolve o problema de "outro desenvolvedor cria um endpoint
novo e esquece de protegê-lo": um endpoint novo já nasce exigindo autenticação;
para torná-lo público é preciso editar esta lista (visível em code review).
Há um teste (`test_deny_by_default_all_routes`) que percorre todas as rotas.

Este middleware só autentica (quem é). Quem pode fazer o quê (papéis, escopos,
ownership) é decidido em `auth/rbac.py` e `auth/ownership.py`.
"""
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from auth.jwt_handler import InvalidToken, TokenUse, decode_token
from auth.principal import Principal
from core.audit import audit
from core.rate_limit import client_ip
from models.users import Role

SESSION_COOKIE = "clinica_session"

PUBLIC_PATHS = frozenset(
    {
        "/",
        "/health",
        "/user/signin",
        "/user/mfa/verify",
        "/oauth/token",
        "/web/login",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/docs/oauth2-redirect",
    }
)
PUBLIC_PREFIXES = ("/static/",)
WEB_PREFIX = "/web/"


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value.strip()
    if request.url.path.startswith(WEB_PREFIX):  # cookie HttpOnly só vale para as páginas
        return request.cookies.get(SESSION_COOKIE)
    return None


def _deny(request: Request, reason: str) -> Response:
    audit("auth_failed", outcome="denied", reason=reason, path=request.url.path, ip=client_ip(request))
    if request.url.path.startswith(WEB_PREFIX):
        return RedirectResponse("/web/login", status_code=303)
    return JSONResponse(
        {"detail": "Credenciais ausentes ou inválidas."},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Preflight CORS não carrega credenciais; o CORSMiddleware (mais externo) o responde.
        if request.method == "OPTIONS" or is_public(request.url.path):
            return await call_next(request)

        token = _extract_token(request)
        if not token:
            return _deny(request, "missing_token")
        try:
            claims = decode_token(token, allowed_uses={TokenUse.access, TokenUse.m2m})
        except InvalidToken as exc:
            return _deny(request, f"invalid_token:{exc}")

        use = TokenUse(claims["token_use"])
        request.state.principal = Principal(
            token_use=use,
            subject=claims["sub"],
            jti=claims["jti"],
            role=Role(claims["role"]) if use is TokenUse.access and "role" in claims else None,
            scopes=frozenset(str(claims.get("scope", "")).split()),
        )
        return await call_next(request)

"""Cabeçalhos de segurança HTTP (Exercício 10).

Obrigatórios do exercício: HSTS, X-Frame-Options, X-Content-Type-Options.
Adicionais: CSP, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP
e Cache-Control: no-store (respostas podem conter dados de saúde).
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# API JSON e páginas HTML internas: nada de script, nada de embed.
CSP_STRICT = (
    "default-src 'none'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)
# Swagger UI / ReDoc carregam assets de CDN e usam script inline.
CSP_DOCS = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'; base-uri 'none'"
)
DOCS_PATHS = ("/docs", "/redoc")

BASE_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
# COEP isolaria a página, mas quebraria o Swagger (scripts de CDN) -> não se aplica a /docs.
# Achado do ZAP (regra 90004, execução real): sem COEP o isolamento de site ficava incompleto.
COEP = ("Cross-Origin-Embedder-Policy", "require-corp")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in BASE_HEADERS.items():
            response.headers[name] = value
        is_docs = request.url.path.startswith(DOCS_PATHS)
        response.headers["Content-Security-Policy"] = CSP_DOCS if is_docs else CSP_STRICT
        if not is_docs:
            response.headers[COEP[0]] = COEP[1]
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

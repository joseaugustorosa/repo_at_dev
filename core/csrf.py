"""CSRF por double-submit cookie para os formulários da página web da recepção."""
import hmac
import secrets

from fastapi import HTTPException, Request, Response, status

from core.config import get_settings

CSRF_COOKIE = "csrf_token"


def get_or_create_token(request: Request) -> str:
    token = request.cookies.get(CSRF_COOKIE)
    return token if token and len(token) >= 32 else secrets.token_urlsafe(32)


def attach_token(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="strict",
        path="/web",
    )


def verify_token(request: Request, form_token: str) -> None:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not form_token or not hmac.compare_digest(cookie, form_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Falha na verificação CSRF.")

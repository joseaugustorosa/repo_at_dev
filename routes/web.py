"""Página HTML interna da recepção: agenda do dia (Exercício 2).

Segurança da renderização:
  * Jinja2 com autoescape LIGADO para HTML (`select_autoescape`) — todo valor
    interpolado em `{{ }}` é codificado; nenhum template usa `|safe`;
  * herança de templates (`base.html` -> `login.html` / `agenda.html`);
  * a página só recebe `AgendaItem` (sem CPF, telefone, anotações clínicas);
  * CSP restritiva (core/security_headers.py): sem script algum, nem inline;
  * sessão em cookie HttpOnly + SameSite=Strict; formulários com token CSRF.
"""
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlmodel import Session

from auth.middleware import SESSION_COOKIE
from auth.rbac import reception_or_admin
from auth.service import authenticate_user, requires_mfa, start_session, verify_mfa
from core import csrf
from core.config import get_settings
from core.rate_limit import enforce_auth_rate_limit
from database.connection import get_session
from database.repository import agenda_for_day
from models.users import User

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(
    env=Environment(
        loader=FileSystemLoader(BASE_DIR / "templates"),
        autoescape=select_autoescape(enabled_extensions=("html",), default=True),
    )
)

web_router = APIRouter(include_in_schema=False)  # páginas HTML ficam fora do OpenAPI da API JSON


def _login_page(request: Request, error: str | None = None, status_code: int = 200):
    token = csrf.get_or_create_token(request)
    response = templates.TemplateResponse(
        request, "login.html", {"csrf_token": token, "error": error}, status_code=status_code
    )
    csrf.attach_token(response, token)
    return response


@web_router.get("/login")
def login_form(request: Request):
    return _login_page(request)


@web_router.post("/login")
def login_submit(
    request: Request,
    session: Session = Depends(get_session),
    username: str = Form(..., max_length=254),
    password: str = Form(..., max_length=72),
    mfa_code: str = Form("", max_length=6),
    csrf_token: str = Form(..., max_length=100),
):
    csrf.verify_token(request, csrf_token)
    enforce_auth_rate_limit(request, "login", username)
    user = authenticate_user(session, username, password)
    generic = "Credenciais inválidas."
    if user is None:
        return _login_page(request, generic, 401)
    if requires_mfa(user) and not (mfa_code and verify_mfa(session, user, mfa_code, "web")):
        return _login_page(request, generic, 401)
    token, ttl = start_session(user, "web")
    response = RedirectResponse("/web/agenda", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,  # inacessível a JavaScript: mitiga roubo de sessão via XSS
        secure=get_settings().cookie_secure,
        samesite="strict",
        path="/web",
    )
    return response


@web_router.get("/agenda")
def agenda_page(
    request: Request,
    day: date | None = None,
    user: User = Depends(reception_or_admin),
    session: Session = Depends(get_session),
):
    selected = day or date.today()
    items = agenda_for_day(session, user, selected)
    token = csrf.get_or_create_token(request)
    response = templates.TemplateResponse(
        request,
        "agenda.html",
        {"day": selected, "items": items, "user_name": user.name, "csrf_token": token},
    )
    csrf.attach_token(response, token)
    return response


@web_router.post("/logout")
def logout(request: Request, csrf_token: str = Form(..., max_length=100)):
    csrf.verify_token(request, csrf_token)
    response = RedirectResponse("/web/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/web")
    return response

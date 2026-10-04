"""Ponto de entrada da API de Agendamento Clínico.

Organização modular (Exercício 1): `routes/` (APIRouter por recurso), `models/`
(tabelas SQLModel + schemas Pydantic), `database/` (engine, sessão, queries) e
`auth/` (identidade, RBAC, ownership). `core/` reúne configuração e controles
transversais (headers, rate limit, auditoria).
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from auth.middleware import JWTAuthMiddleware
from core.config import get_settings
from core.rate_limit import default_rate_limit
from core.security_headers import SecurityHeadersMiddleware
from database.connection import init_db
from routes.appointments import appointment_router
from routes.availability import availability_router
from routes.oauth import oauth_router
from routes.patients import patient_router
from routes.users import user_router
from routes.web import web_router

BASE_DIR = Path(__file__).resolve().parent

# Registro único de routers: usado para montar a app e pelo teste deny-by-default.
ROUTERS = [
    (user_router, "/user"),
    (patient_router, "/patient"),
    (appointment_router, "/appointment"),
    (availability_router, "/availability"),
    (oauth_router, "/oauth"),
    (web_router, "/web"),
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    docs = settings.enable_docs
    app = FastAPI(
        title="API de Agendamento Clínico",
        version="1.0.0",
        description="Pacientes, profissionais de saúde e consultas. Dados de saúde (LGPD art. 11).",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
        dependencies=[Depends(default_rate_limit)],  # limite padrão em todas as rotas
    )

    # Ordem: o ÚLTIMO adicionado é o mais externo. Fluxo da requisição:
    # SecurityHeaders -> CORS -> JWTAuth -> rota. Assim até as respostas 401/429/CORS
    # saem com cabeçalhos de segurança.
    app.add_middleware(JWTAuthMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,  # allowlist explícita (sem "*")
        allow_credentials=False,  # o frontend usa Bearer token, não cookies cross-site
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_: Request, exc: RequestValidationError):
        # O handler padrão ecoa o valor enviado ("input") — inclusive senhas. Removemos.
        errors = [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    for router, prefix in ROUTERS:
        app.include_router(router, prefix=prefix)

    @app.get("/", tags=["Health"])
    def home() -> dict:
        return {"message": "API de Agendamento Clínico"}

    @app.get("/health", tags=["Health"])
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()

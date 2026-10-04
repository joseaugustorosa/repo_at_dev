"""Camada de persistência (Exercício 11): engine, criação de tabelas e sessão por DI.

A URL do banco vem de `Settings` (.env). Todas as consultas da aplicação usam
a API `select()/where()` do SQLModel/SQLAlchemy, que sempre envia valores como
parâmetros ligados (bind parameters) — nenhuma query é montada por
concatenação ou f-string.
"""
from collections.abc import Iterator

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from core.config import get_settings


def _build_engine():
    url = get_settings().database_url
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool  # mesma conexão: banco em memória nos testes
        return create_engine(url, **kwargs)
    return create_engine(url, pool_pre_ping=True)


engine = _build_engine()


def init_db() -> None:
    import models  # noqa: F401  (registra as tabelas no metadata)

    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    """Dependência FastAPI: uma sessão por requisição, fechada ao final."""
    with Session(engine) as session:
        yield session

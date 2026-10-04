"""Autorização por função (RBAC) e por escopo OAuth (M2M).

Modelo adotado (justificativa completa no relatório, Exercício 6):
  * RBAC nas rotas  -> "este papel pode chamar esta operação?"
  * Ownership (ABAC por atributo de dono, em auth/ownership.py)
                    -> "este usuário pode tocar ESTE registro?"
  * Escopos OAuth   -> o que um cliente máquina-a-máquina pode fazer.
RBAC sozinho não impede BOLA; por isso os dois níveis coexistem.
"""
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, Security, status

from auth.authenticate import get_current_user, get_principal, oauth2_m2m
from auth.jwt_handler import TokenUse
from auth.principal import Principal
from core.audit import audit
from models.users import Role, User


def require_roles(*allowed: Role) -> Callable[..., User]:
    def checker(request: Request, user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            audit(
                "access_denied",
                outcome="denied",
                user_id=user.id,
                role=user.role.value,
                path=request.url.path,
                method=request.method,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado para o seu perfil.")
        return user

    return checker


def require_scopes(*needed: str) -> Callable[..., Principal]:
    def checker(
        request: Request,
        principal: Principal = Depends(get_principal),
        _token: str | None = Security(oauth2_m2m, scopes=list(needed)),  # documenta o escopo no OpenAPI
    ) -> Principal:
        # Só clientes M2M carregam escopos; um token de usuário não passa por aqui.
        if principal.token_use is not TokenUse.m2m or not set(needed) <= principal.scopes:
            audit(
                "scope_denied",
                outcome="denied",
                subject=principal.subject,
                token_use=principal.token_use.value,
                path=request.url.path,
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Escopo insuficiente.",
                headers={
                    "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{" ".join(needed)}"'
                },
            )
        return principal

    return checker


# Atalhos nomeados para usar nas rotas
admin_only = require_roles(Role.admin)
staff_any = require_roles(Role.admin, Role.recepcionista, Role.profissional)
professional_only = require_roles(Role.profissional)
admin_or_professional = require_roles(Role.admin, Role.profissional)
reception_or_admin = require_roles(Role.admin, Role.recepcionista)

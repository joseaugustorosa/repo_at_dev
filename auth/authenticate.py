"""Dependências de identidade (quem é a chamada).

A validação criptográfica do token acontece UMA vez, no `JWTAuthMiddleware`.
Aqui só se lê o resultado (`request.state.principal`) e, para usuários humanos,
carrega-se o registro atual do banco: conta desativada ou papel alterado
invalidam o token na hora, sem esperar a expiração.
"""
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlowClientCredentials, OAuthFlows
from fastapi.security import OAuth2, OAuth2PasswordBearer
from sqlmodel import Session

from auth.jwt_handler import TokenUse
from auth.principal import Principal
from database.connection import get_session
from models.users import User

# Esquemas declarados só para o OpenAPI/Swagger (cadeado + botão "Authorize"). O token em
# si já foi verificado pelo middleware. Dois esquemas distintos, porque são dois tipos de
# credencial que NÃO são intercambiáveis: sessão de usuário x cliente máquina-a-máquina.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/signin", auto_error=False)
oauth2_m2m = OAuth2(
    scheme_name="LabClientCredentials",
    flows=OAuthFlows(
        clientCredentials=OAuthFlowClientCredentials(
            tokenUrl="/oauth/token",
            scopes={"availability:read": "Consultar horários livres de um profissional"},
        )
    ),
    auto_error=False,
)


def get_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is None:  # defesa em profundidade: o middleware já teria barrado
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Credenciais ausentes ou inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def get_current_user(
    principal: Principal = Depends(get_principal),
    _token: str | None = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    if principal.token_use is not TokenUse.access:
        # token de cliente máquina-a-máquina não é uma pessoa
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Este token não é de um usuário.")
    user = session.get(User, int(principal.subject))
    if user is None or not user.is_active or user.role != principal.role:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Sessão inválida. Faça login novamente.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Annotated

from fastapi import Form
from pydantic import EmailStr, Field, StringConstraints, field_validator
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel

from models.base import NAME_PATTERN, PublicModel, StrictModel, utcnow


class Role(str, Enum):
    admin = "admin"
    recepcionista = "recepcionista"
    profissional = "profissional"


# ----------------------------- tabela --------------------------------------
class User(SQLModel, table=True):
    __tablename__ = "users"

    id: int | None = SQLField(default=None, primary_key=True)
    name: str
    email: str = SQLField(index=True, unique=True)
    password_hash: str  # bcrypt; a senha em texto plano nunca é armazenada
    role: Role = SQLField(default=Role.recepcionista)
    is_active: bool = SQLField(default=True)
    mfa_seed: str | None = SQLField(default=None)  # semente aleatória; ver auth/mfa.py
    mfa_last_step: int | None = SQLField(default=None)  # anti-replay do TOTP
    created_at: datetime = SQLField(default_factory=utcnow)


# ----------------------------- entrada -------------------------------------
class UserCreate(StrictModel):
    name: Annotated[str, StringConstraints(pattern=NAME_PATTERN)]
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)
    role: Role

    @field_validator("password")
    @classmethod
    def _bcrypt_byte_limit(cls, v: str) -> str:
        if len(v.encode()) > 72:  # bcrypt ignora/recusa bytes além de 72
            raise ValueError("senha excede 72 bytes")
        return v


@dataclass
class SignInForm:
    username: str
    password: str


def signin_form(
    username: str = Form(..., max_length=254),
    password: str = Form(..., max_length=72),
    # Campos opcionais do formulário OAuth2 (o Swagger "Authorize" os envia); ignorados, mas limitados.
    grant_type: str | None = Form(None, pattern="^password$", max_length=8),
    scope: str = Form("", max_length=200),
    client_id: str | None = Form(None, max_length=100),
    client_secret: str | None = Form(None, max_length=200),
) -> SignInForm:
    """Substitui `OAuth2PasswordRequestForm`, que não declara limites de tamanho na spec."""
    return SignInForm(username=username, password=password)


class MFAVerifyRequest(StrictModel):
    mfa_token: str = Field(min_length=20, max_length=2048)
    code: str = Field(pattern=r"^\d{6}$")


# ----------------------------- saída ---------------------------------------
class UserPublic(PublicModel):
    id: int
    name: str
    email: EmailStr
    role: Role
    is_active: bool


class UserCreated(UserPublic):
    # Exibido uma única vez, só para contas com MFA obrigatório (admin).
    mfa_provisioning_uri: str | None = None


class TokenResponse(PublicModel):
    access_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int | None = None
    mfa_required: bool = False
    mfa_token: str | None = None

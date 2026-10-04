import re
from datetime import datetime
from typing import Annotated

from pydantic import EmailStr, Field, StringConstraints, field_validator
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel

from models.base import NAME_PATTERN, PHONE_PATTERN, PublicModel, StrictModel, is_valid_cpf, utcnow


# ----------------------------- tabela --------------------------------------
class Patient(SQLModel, table=True):
    __tablename__ = "patients"

    id: int | None = SQLField(default=None, primary_key=True)
    name: str
    cpf: str = SQLField(index=True, unique=True)  # dado pessoal: nunca devolvido por inteiro
    phone: str
    email: str | None = None
    professional_id: int = SQLField(foreign_key="users.id", index=True)  # profissional responsável
    created_by_user_id: int | None = None  # auditoria interna
    created_at: datetime = SQLField(default_factory=utcnow)


# ----------------------------- entrada -------------------------------------
class PatientCreate(StrictModel):
    name: Annotated[str, StringConstraints(pattern=NAME_PATTERN)]
    cpf: Annotated[str, StringConstraints(pattern=r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$", max_length=14)]
    phone: Annotated[str, StringConstraints(pattern=PHONE_PATTERN)]
    email: EmailStr | None = None
    professional_id: int = Field(gt=0)

    @field_validator("cpf")
    @classmethod
    def _cpf(cls, v: str) -> str:
        if not is_valid_cpf(v):
            raise ValueError("CPF inválido")
        return re.sub(r"\D", "", v)  # armazena só dígitos


# ----------------------------- saída ---------------------------------------
class PatientPublic(PublicModel):
    id: int
    name: str
    cpf: str  # sempre mascarado (minimização de dados — LGPD)
    phone: str
    email: str | None = None
    professional_id: int

    @field_validator("cpf")
    @classmethod
    def _mask_cpf(cls, v: str) -> str:
        digits = re.sub(r"\D", "", v)
        if len(digits) == 11:
            return f"***.***.***-{digits[-2:]}"
        return v

from datetime import date, datetime, time
from enum import Enum
from typing import Annotated

from pydantic import Field, NaiveDatetime, StringConstraints, field_validator
from sqlalchemy import Index, text
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel

from models.base import NOTES_PATTERN, REASON_PATTERN, PublicModel, StrictModel, utcnow


class AppointmentStatus(str, Enum):
    agendada = "agendada"
    cancelada = "cancelada"
    concluida = "concluida"


# ----------------------------- tabela --------------------------------------
class Appointment(SQLModel, table=True):
    __tablename__ = "appointments"
    # Um profissional não pode ter duas consultas ativas no mesmo horário.
    __table_args__ = (
        Index(
            "uq_professional_slot_active",
            "professional_id",
            "date_time",
            unique=True,
            sqlite_where=text("status != 'cancelada'"),
            postgresql_where=text("status != 'cancelada'"),
        ),
    )

    id: int | None = SQLField(default=None, primary_key=True)
    patient_id: int = SQLField(foreign_key="patients.id", index=True)
    professional_id: int = SQLField(foreign_key="users.id", index=True)
    date_time: NaiveDatetime = SQLField(index=True)  # horário local da clínica, sem fuso
    status: AppointmentStatus = SQLField(default=AppointmentStatus.agendada)
    reason: str  # motivo (não clínico) — exibido na agenda da recepção
    notes: str | None = None  # anotações clínicas (prontuário) — restritas

    # ---- Campos INTERNOS de auditoria: não podem aparecer em nenhuma resposta ----
    created_by_user_id: int | None = None
    created_at: datetime = SQLField(default_factory=utcnow)
    updated_at: datetime = SQLField(default_factory=utcnow)
    created_from_ip: str | None = None
    internal_audit_note: str | None = None


# ----------------------------- entrada -------------------------------------
Reason = Annotated[str, StringConstraints(pattern=REASON_PATTERN)]
Notes = Annotated[str, StringConstraints(pattern=NOTES_PATTERN)]


def _validate_slot(v: datetime) -> datetime:
    # NaiveDatetime já rejeita valores com fuso (informe o horário local, ex.: 2026-10-10T10:00:00)
    if v.minute not in (0, 30) or v.second or v.microsecond:
        raise ValueError("horários devem estar alinhados em blocos de 30 minutos")
    return v


class AppointmentCreate(StrictModel):
    # professional_id NÃO é aceito do cliente: vem do token (evita BOLA/mass assignment).
    patient_id: int = Field(gt=0)
    date_time: NaiveDatetime
    reason: Reason
    notes: Notes | None = None

    @field_validator("date_time")
    @classmethod
    def _slot_and_future(cls, v: datetime) -> datetime:
        v = _validate_slot(v)
        if v <= datetime.now():
            raise ValueError("a consulta deve ser agendada para o futuro")
        return v


class AppointmentUpdate(StrictModel):
    date_time: NaiveDatetime | None = None
    reason: Reason | None = None
    notes: Notes | None = None
    status: AppointmentStatus | None = None

    @field_validator("date_time")
    @classmethod
    def _slot(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _validate_slot(v)


# ----------------------------- saída ---------------------------------------
class AppointmentPublic(PublicModel):
    """Whitelist de campos devolvidos pela API. created_by_user_id, created_at,
    updated_at, created_from_ip e internal_audit_note ficam de fora de propósito."""

    id: int
    patient_id: int
    professional_id: int
    date_time: NaiveDatetime
    status: AppointmentStatus
    reason: str
    notes: str | None = None


class AgendaItem(PublicModel):
    """Visão da recepção: sem anotações clínicas, sem CPF, sem telefone."""

    id: int
    date_time: datetime
    status: AppointmentStatus
    reason: str
    patient_name: str
    professional_name: str


class AvailabilityResponse(PublicModel):
    """Visão do laboratório parceiro: só horários livres — nenhum dado de paciente."""

    professional_id: int
    day: date
    slot_minutes: int
    available_slots: list[time]

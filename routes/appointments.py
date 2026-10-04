from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from auth.ownership import get_appointment_or_404, get_patient_or_404
from auth.rbac import admin_or_professional, professional_only, staff_any
from core.audit import audit
from core.openapi import OWNED_RESOURCE_RESPONSES
from core.rate_limit import client_ip
from database.connection import get_session
from database.repository import agenda_for_day, list_appointments
from models.appointments import (
    AgendaItem,
    Appointment,
    AppointmentCreate,
    AppointmentPublic,
    AppointmentStatus,
    AppointmentUpdate,
)
from models.base import utcnow
from models.users import User

appointment_router = APIRouter(tags=["Appointments"], responses=OWNED_RESOURCE_RESPONSES)

def _slot_taken() -> HTTPException:  # fábrica: não reutilizar a mesma instância de exceção entre requisições
    return HTTPException(status.HTTP_409_CONFLICT, "Horário já ocupado para este profissional.")


@appointment_router.post("/new", response_model=AppointmentPublic, status_code=status.HTTP_201_CREATED)
def create_appointment(
    request: Request,
    body: AppointmentCreate,
    user: User = Depends(professional_only),
    session: Session = Depends(get_session),
) -> Appointment:
    """Somente profissionais agendam, e só para os próprios pacientes. O
    `professional_id` é o do token — o cliente não pode escolher outro."""
    patient = get_patient_or_404(session, user, body.patient_id)  # ownership do paciente
    appointment = Appointment(
        patient_id=patient.id,
        professional_id=user.id,
        date_time=body.date_time,
        reason=body.reason,
        notes=body.notes,
        created_by_user_id=user.id,
        created_from_ip=client_ip(request),
    )
    session.add(appointment)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise _slot_taken() from None
    session.refresh(appointment)
    audit("appointment_created", outcome="success", actor_id=user.id, appointment_id=appointment.id)
    return appointment


@appointment_router.get("/", response_model=list[AppointmentPublic])
def read_appointments(
    status_filter: AppointmentStatus | None = Query(None, alias="status"),
    date_from: date | None = None,
    date_to: date | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(admin_or_professional),
    session: Session = Depends(get_session),
) -> list[Appointment]:
    return list_appointments(session, user, status_filter, date_from, date_to, limit, offset)


# Declarada ANTES de "/{appointment_id}".
@appointment_router.get("/agenda", response_model=list[AgendaItem])
def read_agenda(
    day: date | None = None,
    user: User = Depends(staff_any),
    session: Session = Depends(get_session),
) -> list[AgendaItem]:
    """Agenda do dia (JSON). Sem anotações clínicas: serve também à recepção."""
    return agenda_for_day(session, user, day or date.today())


@appointment_router.get("/{appointment_id}", response_model=AppointmentPublic)
def read_appointment(
    appointment_id: int = Path(gt=0),
    user: User = Depends(admin_or_professional),
    session: Session = Depends(get_session),
) -> Appointment:
    return get_appointment_or_404(session, user, appointment_id)


@appointment_router.put("/{appointment_id}", response_model=AppointmentPublic)
def update_appointment(
    body: AppointmentUpdate,
    appointment_id: int = Path(gt=0),
    user: User = Depends(professional_only),
    session: Session = Depends(get_session),
) -> Appointment:
    appointment = get_appointment_or_404(session, user, appointment_id)
    if appointment.status is not AppointmentStatus.agendada:
        raise HTTPException(status.HTTP_409_CONFLICT, "Somente consultas agendadas podem ser alteradas.")
    changes = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None or k == "notes"}
    if "date_time" in changes and changes["date_time"] <= datetime.now():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A nova data deve estar no futuro.")
    for field, value in changes.items():  # só campos da whitelist de AppointmentUpdate
        setattr(appointment, field, value)
    appointment.updated_at = utcnow()
    session.add(appointment)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise _slot_taken() from None
    session.refresh(appointment)
    audit("appointment_updated", outcome="success", actor_id=user.id, appointment_id=appointment.id,
          fields=sorted(changes))
    return appointment


@appointment_router.delete("/{appointment_id}", response_model=AppointmentPublic)
def cancel_appointment(
    appointment_id: int = Path(gt=0),
    user: User = Depends(admin_or_professional),
    session: Session = Depends(get_session),
) -> Appointment:
    """Cancelamento lógico (mantém o histórico para auditoria)."""
    appointment = get_appointment_or_404(session, user, appointment_id)
    appointment.status = AppointmentStatus.cancelada
    appointment.updated_at = utcnow()
    session.add(appointment)
    session.commit()
    session.refresh(appointment)
    audit("appointment_cancelled", outcome="success", actor_id=user.id, appointment_id=appointment.id)
    return appointment

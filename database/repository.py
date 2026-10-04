"""Consultas reutilizáveis. Todas parametrizadas via SQLModel `select().where()`."""
from datetime import date, datetime, time, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from auth.ownership import scope_appointments, scope_patients
from models.appointments import AgendaItem, Appointment, AppointmentStatus
from models.patients import Patient
from models.users import Role, User

WORK_START = time(8, 0)
WORK_END = time(18, 0)
SLOT_MINUTES = 30
MAX_AGENDA_ROWS = 500


def agenda_for_day(session: Session, user: User, day: date) -> list[AgendaItem]:
    """Agenda do dia (visão da recepção): nome do paciente e do profissional,
    horário, motivo e status. Nada de CPF, telefone ou anotações clínicas."""
    start = datetime.combine(day, time.min)
    stmt = (
        select(Appointment, Patient, User)
        .join(Patient, Appointment.patient_id == Patient.id)
        .join(User, Appointment.professional_id == User.id)
        .where(Appointment.date_time >= start, Appointment.date_time < start + timedelta(days=1))
        .order_by(Appointment.date_time)
        .limit(MAX_AGENDA_ROWS)
    )
    if user.role is Role.profissional:  # profissional vê apenas a própria agenda
        stmt = stmt.where(Appointment.professional_id == user.id)
    return [
        AgendaItem(
            id=appt.id,
            date_time=appt.date_time,
            status=appt.status,
            reason=appt.reason,
            patient_name=patient.name,
            professional_name=prof.name,
        )
        for appt, patient, prof in session.exec(stmt).all()
    ]


def search_patients_by_name(session: Session, user: User, name: str, limit: int, offset: int) -> list[Patient]:
    # `contains(..., autoescape=True)` -> LIKE com o termo como parâmetro e '%', '_' escapados.
    stmt = scope_patients(
        select(Patient).where(func.lower(Patient.name).contains(name.lower(), autoescape=True)), user
    )
    return list(session.exec(stmt.order_by(Patient.name).limit(limit).offset(offset)).all())


def list_appointments(
    session: Session,
    user: User,
    status: AppointmentStatus | None,
    date_from: date | None,
    date_to: date | None,
    limit: int,
    offset: int,
) -> list[Appointment]:
    stmt = scope_appointments(select(Appointment), user)
    if status is not None:
        stmt = stmt.where(Appointment.status == status)
    if date_from is not None:
        stmt = stmt.where(Appointment.date_time >= datetime.combine(date_from, time.min))
    if date_to is not None:
        stmt = stmt.where(Appointment.date_time < datetime.combine(date_to + timedelta(days=1), time.min))
    return list(session.exec(stmt.order_by(Appointment.date_time).limit(limit).offset(offset)).all())


def free_slots(session: Session, professional_id: int, day: date) -> list[time]:
    """Horários livres do dia (seg–sex, 08:00–18:00, blocos de 30 min)."""
    if day.weekday() >= 5:
        return []
    start = datetime.combine(day, time.min)
    booked = set(
        session.exec(
            select(Appointment.date_time).where(
                Appointment.professional_id == professional_id,
                Appointment.status != AppointmentStatus.cancelada,
                Appointment.date_time >= start,
                Appointment.date_time < start + timedelta(days=1),
            )
        ).all()
    )
    now = datetime.now()
    slots: list[time] = []
    cursor, end = datetime.combine(day, WORK_START), datetime.combine(day, WORK_END)
    while cursor < end:
        if cursor not in booked and cursor > now:
            slots.append(cursor.time())
        cursor += timedelta(minutes=SLOT_MINUTES)
    return slots

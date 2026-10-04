"""Verificação de ownership (BOLA / API1:2023) — fonte única da regra "quem vê o quê".

O filtro é aplicado DENTRO da query SQL (cláusula WHERE parametrizada), não depois:
um registro de outro dono simplesmente não é retornado, e a rota responde 404
tanto para "não existe" quanto para "não é seu", evitando enumeração de IDs.
"""
from fastapi import HTTPException, status
from sqlalchemy import false
from sqlmodel import Session, select
from sqlmodel.sql.expression import SelectOfScalar

from core.audit import audit
from models.appointments import Appointment
from models.patients import Patient
from models.users import Role, User


def scope_appointments(stmt: SelectOfScalar, user: User) -> SelectOfScalar:
    if user.role is Role.admin:
        return stmt
    if user.role is Role.profissional:
        return stmt.where(Appointment.professional_id == user.id)
    return stmt.where(false())  # recepção não acessa consultas com anotações clínicas


def scope_patients(stmt: SelectOfScalar, user: User) -> SelectOfScalar:
    if user.role is Role.profissional:
        return stmt.where(Patient.professional_id == user.id)
    return stmt  # admin e recepção administram o cadastro


def _not_found(message: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, message)


def get_appointment_or_404(session: Session, user: User, appointment_id: int) -> Appointment:
    stmt = scope_appointments(select(Appointment).where(Appointment.id == appointment_id), user)
    found = session.exec(stmt).first()
    if found is None:
        if session.get(Appointment, appointment_id) is not None:  # existe, mas é de outro dono
            audit("object_access_denied", outcome="denied", user_id=user.id,
                  resource="appointment", resource_id=appointment_id)
        raise _not_found("Consulta não encontrada.")
    return found


def get_patient_or_404(session: Session, user: User, patient_id: int) -> Patient:
    stmt = scope_patients(select(Patient).where(Patient.id == patient_id), user)
    found = session.exec(stmt).first()
    if found is None:
        if session.get(Patient, patient_id) is not None:
            audit("object_access_denied", outcome="denied", user_id=user.id,
                  resource="patient", resource_id=patient_id)
        raise _not_found("Paciente não encontrado.")
    return found

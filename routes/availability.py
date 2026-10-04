"""Consulta de horários livres — consumida pelo laboratório parceiro (M2M, Exercício 7).

Exige token do tipo `m2m` com o escopo `availability:read`. Devolve somente
horários; nenhum dado de paciente. Um profissional autenticado (token `access`)
NÃO acessa esta rota, e o token do laboratório NÃO acessa nenhuma outra.
"""
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select

from auth.principal import Principal
from auth.rbac import require_scopes
from core.openapi import PROTECTED_RESPONSES
from database.connection import get_session
from database.repository import SLOT_MINUTES, free_slots
from models.appointments import AvailabilityResponse
from models.users import Role, User

availability_router = APIRouter(tags=["Availability (laboratório M2M)"], responses=PROTECTED_RESPONSES)

MAX_DAYS_AHEAD = 60


@availability_router.get("/", response_model=AvailabilityResponse)
def read_availability(
    professional_id: int = Query(..., gt=0),
    day: date = Query(..., description="Data (YYYY-MM-DD), até 60 dias à frente"),
    _client: Principal = Depends(require_scopes("availability:read")),
    session: Session = Depends(get_session),
) -> AvailabilityResponse:
    today = date.today()
    if not today <= day <= today + timedelta(days=MAX_DAYS_AHEAD):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Data fora da janela permitida.")
    professional = session.exec(
        select(User).where(
            User.id == professional_id, User.role == Role.profissional, User.is_active.is_(True)
        )
    ).first()
    if professional is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Profissional não encontrado.")
    return AvailabilityResponse(
        professional_id=professional.id,
        day=day,
        slot_minutes=SLOT_MINUTES,
        available_slots=free_slots(session, professional.id, day),
    )

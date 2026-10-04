from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from auth.ownership import get_patient_or_404, scope_patients
from auth.rbac import staff_any
from core.audit import audit
from core.openapi import OWNED_RESOURCE_RESPONSES
from database.connection import get_session
from database.repository import search_patients_by_name
from models.base import SEARCH_PATTERN
from models.patients import Patient, PatientCreate, PatientPublic
from models.users import Role, User

patient_router = APIRouter(tags=["Patients"], responses=OWNED_RESOURCE_RESPONSES)


@patient_router.post("/new", response_model=PatientPublic, status_code=status.HTTP_201_CREATED)
def create_patient(
    body: PatientCreate,
    user: User = Depends(staff_any),
    session: Session = Depends(get_session),
) -> Patient:
    if user.role is Role.profissional and body.professional_id != user.id:
        audit("object_access_denied", outcome="denied", user_id=user.id,
              resource="patient_create", resource_id=body.professional_id)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Profissionais só cadastram os próprios pacientes.")
    owner = session.exec(
        select(User).where(
            User.id == body.professional_id, User.role == Role.profissional, User.is_active.is_(True)
        )
    ).first()
    if owner is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Profissional responsável inválido.")
    patient = Patient(**body.model_dump(), created_by_user_id=user.id)
    session.add(patient)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Paciente já cadastrado.") from None
    session.refresh(patient)
    audit("patient_created", outcome="success", actor_id=user.id, patient_id=patient.id)
    return patient


@patient_router.get("/", response_model=list[PatientPublic])
def list_patients(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(staff_any),
    session: Session = Depends(get_session),
) -> list[Patient]:
    stmt = scope_patients(select(Patient), user).order_by(Patient.id).limit(limit).offset(offset)
    return list(session.exec(stmt).all())


# Declarada ANTES de "/{patient_id}" para que "search" não seja lido como ID.
@patient_router.get("/search", response_model=list[PatientPublic])
def search_patients(
    name: str = Query(..., pattern=SEARCH_PATTERN, description="Parte do nome (2–60 letras)"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(staff_any),
    session: Session = Depends(get_session),
) -> list[Patient]:
    return search_patients_by_name(session, user, name, limit, offset)


@patient_router.get("/{patient_id}", response_model=PatientPublic)
def read_patient(
    patient_id: int = Path(gt=0),
    user: User = Depends(staff_any),
    session: Session = Depends(get_session),
) -> Patient:
    return get_patient_or_404(session, user, patient_id)

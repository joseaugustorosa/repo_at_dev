from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from auth import mfa
from auth.authenticate import get_current_user
from auth.hash_password import HashPassword
from auth.jwt_handler import InvalidToken, TokenUse, decode_token
from auth.rbac import admin_only
from auth.service import (
    MFA_REQUIRED_ROLES,
    authenticate_user,
    issue_access_token,
    issue_mfa_challenge,
    requires_mfa,
    verify_mfa,
)
from core.audit import audit
from core.openapi import AUTH_RESPONSES, PROTECTED_RESPONSES
from core.rate_limit import enforce_auth_rate_limit
from database.connection import get_session
from models.users import (
    MFAVerifyRequest,
    SignInForm,
    TokenResponse,
    User,
    UserCreate,
    UserCreated,
    UserPublic,
    signin_form,
)

user_router = APIRouter(tags=["Users"])
hasher = HashPassword()

def _invalid_credentials() -> HTTPException:
    # Fábrica (não instância global): relançar o MESMO objeto acumula traceback entre requisições.
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Credenciais inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )


@user_router.post("/signin", response_model=TokenResponse, response_model_exclude_none=True, responses=AUTH_RESPONSES)
def sign_in(
    request: Request,
    form: SignInForm = Depends(signin_form),
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Login (OAuth2 Password flow). Contas admin recebem um desafio MFA em vez de
    um access token; conclua em `POST /user/mfa/verify`."""
    username = form.username
    enforce_auth_rate_limit(request, "login", username)  # 5/min por IP e por conta
    user = authenticate_user(session, username, form.password)
    if user is None:
        raise _invalid_credentials()
    return issue_mfa_challenge(user) if requires_mfa(user) else issue_access_token(user)


@user_router.post("/mfa/verify", response_model=TokenResponse, response_model_exclude_none=True, responses=AUTH_RESPONSES)
def mfa_verify(
    request: Request,
    body: MFAVerifyRequest,
    session: Session = Depends(get_session),
) -> TokenResponse:
    """Segundo fator (TOTP). Troca o `mfa_token` + código por um access token."""
    try:
        claims = decode_token(body.mfa_token, allowed_uses={TokenUse.mfa})
    except InvalidToken:
        raise _invalid_credentials() from None
    enforce_auth_rate_limit(request, "mfa", claims["sub"])
    user = session.get(User, int(claims["sub"]))
    if user is None or not user.is_active or not verify_mfa(session, user, body.code, "api"):
        raise _invalid_credentials()
    return issue_access_token(user)


@user_router.post("/signup", response_model=UserCreated, status_code=status.HTTP_201_CREATED, responses=PROTECTED_RESPONSES)
def create_user(
    body: UserCreate,
    admin: User = Depends(admin_only),
    session: Session = Depends(get_session),
) -> UserCreated:
    """Cria usuário interno. Restrito a administradores: não existe auto-cadastro,
    e o papel nunca é escolhido por quem não é admin (antes: mass assignment)."""
    user = User(
        name=body.name,
        email=body.email.lower(),
        password_hash=hasher.create_hash(body.password),
        role=body.role,
        mfa_seed=mfa.new_seed() if body.role in MFA_REQUIRED_ROLES else None,
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "E-mail já cadastrado.") from None
    session.refresh(user)
    audit("user_created", outcome="success", actor_id=admin.id, user_id=user.id, role=user.role.value)
    created = UserCreated.model_validate(user)
    if user.mfa_seed:
        created.mfa_provisioning_uri = mfa.provisioning_uri(user)  # mostrado só agora
    return created


@user_router.get("/me", response_model=UserPublic, responses=PROTECTED_RESPONSES)
def read_me(user: User = Depends(get_current_user)) -> User:
    return user


@user_router.get("/", response_model=list[UserPublic], responses=PROTECTED_RESPONSES)
def list_users(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    _admin: User = Depends(admin_only),
    session: Session = Depends(get_session),
) -> list[User]:
    return list(session.exec(select(User).order_by(User.id).limit(limit).offset(offset)).all())


@user_router.patch("/{user_id}/deactivate", response_model=UserPublic, responses=PROTECTED_RESPONSES)
def deactivate_user(
    user_id: int = Path(gt=0),
    admin: User = Depends(admin_only),
    session: Session = Depends(get_session),
) -> User:
    target = session.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado.")
    if target.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Você não pode desativar a própria conta.")
    target.is_active = False  # tokens já emitidos deixam de valer (get_current_user consulta o banco)
    session.add(target)
    session.commit()
    session.refresh(target)
    audit("user_deactivated", outcome="success", actor_id=admin.id, user_id=target.id)
    return target

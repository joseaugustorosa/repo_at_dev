"""Fluxo de login compartilhado pela API (/user/signin) e pela página web (/web/login).

Concentra a verificação de credenciais e a emissão de token para que a regra
(MFA obrigatório para admin, mensagens genéricas, auditoria) exista num só lugar.
"""
from datetime import timedelta

from sqlmodel import Session, select

from auth import mfa
from auth.hash_password import HashPassword
from auth.jwt_handler import TokenUse, access_ttl, create_token, mfa_ttl
from core.audit import audit, fingerprint
from models.users import Role, TokenResponse, User

hasher = HashPassword()
MFA_REQUIRED_ROLES = {Role.admin}


def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = session.exec(select(User).where(User.email == email.strip().lower())).first()
    if user is None or not user.is_active:
        hasher.burn_cpu(password)  # mesmo custo de tempo, com ou sem usuário
        audit("login", outcome="failure", reason="unknown_or_inactive", id=fingerprint(email))
        return None
    if not hasher.verify_hash(password, user.password_hash):
        audit("login", outcome="failure", reason="bad_password", user_id=user.id)
        return None
    return user


def start_session(user: User, channel: str) -> tuple[str, timedelta]:
    """ÚNICO ponto que emite o token de sessão (API e página web): claims, TTL e auditoria."""
    ttl = access_ttl()
    token = create_token(
        subject=str(user.id),
        token_use=TokenUse.access,
        ttl=ttl,
        extra_claims={"role": user.role.value},
    )
    audit("login", outcome="success", user_id=user.id, role=user.role.value, channel=channel)
    return token, ttl


def issue_access_token(user: User, channel: str = "api") -> TokenResponse:
    token, ttl = start_session(user, channel)
    return TokenResponse(access_token=token, expires_in=int(ttl.total_seconds()))


def verify_mfa(session: Session, user: User, code: str, channel: str) -> bool:
    """ÚNICO ponto que valida o 2º fator: confere o TOTP, audita falha e persiste o anti-replay."""
    if not mfa.verify_code(user, code):
        audit("mfa", outcome="failure", user_id=user.id, channel=channel)
        return False
    session.add(user)  # grava mfa_last_step
    session.commit()
    return True


def issue_mfa_challenge(user: User) -> TokenResponse:
    token = create_token(subject=str(user.id), token_use=TokenUse.mfa, ttl=mfa_ttl())
    audit("login", outcome="mfa_challenge", user_id=user.id)
    return TokenResponse(mfa_required=True, mfa_token=token)


def requires_mfa(user: User) -> bool:
    return user.role in MFA_REQUIRED_ROLES

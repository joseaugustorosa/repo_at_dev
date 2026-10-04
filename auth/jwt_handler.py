"""Emissão e validação de JWT (Exercícios 6 e 7).

Três tipos de token, distinguidos pela claim `token_use`:
  * access — sessão de usuário humano (claims: sub=id do usuário, role);
  * mfa    — prova intermediária de senha válida; só serve em /user/mfa/verify;
  * m2m    — cliente máquina-a-máquina (claims: sub=client_id, scope).

Validação rígida: algoritmo fixo (sem "none"), exp/iat/nbf/iss/aud/jti/sub
obrigatórios. O segredo vem de Settings, nunca do código.
"""
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum

import jwt

from core.config import get_settings

REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "token_use"]


class TokenUse(str, Enum):
    access = "access"
    mfa = "mfa"
    m2m = "m2m"


class InvalidToken(Exception):
    """Token ausente de claims, expirado, adulterado ou de tipo inesperado."""


def create_token(
    *,
    subject: str,
    token_use: TokenUse,
    ttl: timedelta,
    extra_claims: dict | None = None,
) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "iss": s.jwt_issuer,
        "aud": s.jwt_audience,
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
        "token_use": token_use.value,
        **(extra_claims or {}),
    }
    return jwt.encode(payload, s.jwt_secret_key.get_secret_value(), algorithm=s.jwt_algorithm)


def decode_token(token: str, *, allowed_uses: set[TokenUse] | None = None) -> dict:
    s = get_settings()
    try:
        claims = jwt.decode(
            token,
            s.jwt_secret_key.get_secret_value(),
            algorithms=[s.jwt_algorithm],  # allowlist: rejeita alg=none / troca de algoritmo
            audience=s.jwt_audience,
            issuer=s.jwt_issuer,
            options={"require": REQUIRED_CLAIMS},
        )
        use = TokenUse(claims["token_use"])
    except (jwt.PyJWTError, ValueError) as exc:
        raise InvalidToken(type(exc).__name__) from exc
    if allowed_uses is not None and use not in allowed_uses:
        raise InvalidToken("token_use inesperado")
    return claims


# -- atalhos de TTL (tempos curtos limitam a janela de uso de um token vazado) --
def access_ttl() -> timedelta:
    return timedelta(minutes=get_settings().access_token_ttl_minutes)


def mfa_ttl() -> timedelta:
    return timedelta(minutes=get_settings().mfa_token_ttl_minutes)


def m2m_ttl() -> timedelta:
    return timedelta(minutes=get_settings().m2m_token_ttl_minutes)

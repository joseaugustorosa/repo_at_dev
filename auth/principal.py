from dataclasses import dataclass, field

from auth.jwt_handler import TokenUse
from models.users import Role


@dataclass(frozen=True)
class Principal:
    """Identidade autenticada extraída de um JWT já validado."""

    token_use: TokenUse
    subject: str  # id do usuário (access) ou client_id (m2m)
    jti: str
    role: Role | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)

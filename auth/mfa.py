"""MFA simulado por TOTP (RFC 6238) — Exercício 6.

"Simulado" porque não há tela de cadastro com QR Code nem recuperação de conta,
mas o algoritmo é o real e compatível com Google Authenticator/FreeOTP.

Decisão de segurança: o banco guarda apenas uma *semente aleatória* por usuário.
O segredo TOTP é derivado por HMAC com `MFA_MASTER_KEY` (fora do banco). Assim,
um dump do banco, sozinho, não permite gerar códigos MFA.
Anti-replay: o último passo de 30 s aceito é gravado; reutilizar o código é negado.
"""
import base64
import hashlib
import hmac
import secrets
import time

import pyotp

from core.config import get_settings
from models.users import User

INTERVAL = 30


def _require_seed(user: User) -> str:
    if not user.mfa_seed:  # explícito (assert some com `python -O`)
        raise ValueError("usuário sem MFA configurado")
    return user.mfa_seed


def new_seed() -> str:
    return secrets.token_hex(16)


def _totp(seed: str) -> pyotp.TOTP:
    master = get_settings().mfa_master_key.get_secret_value().encode()
    key = hmac.new(master, f"mfa:{seed}".encode(), hashlib.sha256).digest()[:20]
    return pyotp.TOTP(base64.b32encode(key).decode(), interval=INTERVAL)


def provisioning_uri(user: User) -> str:
    return _totp(_require_seed(user)).provisioning_uri(name=user.email, issuer_name="Clinica API")


def current_code(user: User) -> str:
    """Apenas para testes e demonstração (um app autenticador faria isto)."""
    return _totp(_require_seed(user)).now()


def verify_code(user: User, code: str, *, now: float | None = None) -> bool:
    """Valida o código (janela ±1 passo) e registra o passo usado contra replay.
    O chamador deve fazer commit da sessão para persistir `mfa_last_step`."""
    if not user.mfa_seed:
        return False
    totp = _totp(user.mfa_seed)
    current_step = int(now if now is not None else time.time()) // INTERVAL
    for step in (current_step - 1, current_step, current_step + 1):
        if user.mfa_last_step is not None and step <= user.mfa_last_step:
            continue
        if hmac.compare_digest(totp.at(step * INTERVAL), code):
            user.mfa_last_step = step
            return True
    return False

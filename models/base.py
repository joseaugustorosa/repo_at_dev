"""Blocos reutilizados pelos modelos: base estrita e validadores whitelist/regex."""
import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Base de TODO corpo de requisição.

    * extra="forbid": campo não declarado => 422 (bloqueia mass assignment,
      ex.: enviar "role": "admin" ou "professional_id" que não deveria vir do cliente);
    * str_strip_whitespace: normaliza entrada antes de validar.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PublicModel(BaseModel):
    """Base de respostas: serializa a partir de objetos ORM, expondo só o declarado."""

    model_config = ConfigDict(from_attributes=True)


# --- Whitelists (regex) -----------------------------------------------------
# Nomes: letras (com acentos), espaço, apóstrofo, ponto e hífen.
NAME_PATTERN = r"^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ .'\-]{1,99}$"
# Texto livre (motivo / anotações): letras, dígitos, espaços e pontuação comum.
# Exclui deliberadamente < > & ` { } \ $ ; ... => nenhum marcador HTML/script passa.
FREE_TEXT_ALLOWED = r"A-Za-z0-9À-ÖØ-öø-ÿ\s.,;:!?()\-_/%+ºª°'\""
REASON_PATTERN = rf"^[{FREE_TEXT_ALLOWED}]{{3,120}}$"
NOTES_PATTERN = rf"^[{FREE_TEXT_ALLOWED}]{{0,2000}}$"
PHONE_PATTERN = r"^\+?\d{10,13}$"
SEARCH_PATTERN = r"^[A-Za-zÀ-ÖØ-öø-ÿ .'\-]{2,60}$"


def is_valid_cpf(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11 or digits == digits[0] * 11:
        return False
    for i in (9, 10):
        total = sum(int(digits[n]) * (i + 1 - n) for n in range(i))
        if (total * 10 % 11) % 10 != int(digits[i]):
            return False
    return True

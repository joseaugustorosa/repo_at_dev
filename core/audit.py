"""Trilha de auditoria de eventos de segurança (mitiga "R" do STRIDE).

Regras: um evento por linha em JSON; nunca registrar senha, token, CPF ou
conteúdo clínico. Identificadores de login desconhecido são registrados só
como hash truncado, para correlação sem armazenar PII.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("clinica.audit")


def fingerprint(value: str) -> str:
    """Hash curto e não reversível de um identificador (ex.: e-mail digitado)."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()[:12]


def audit(event: str, *, outcome: str, **details: object) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "outcome": outcome,
        **details,
    }
    level = logging.WARNING if outcome in {"denied", "failure"} else logging.INFO
    logger.log(level, json.dumps(record, ensure_ascii=False, default=str))

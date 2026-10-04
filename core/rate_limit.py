"""Rate limiting por janela deslizante (Exercício 10).

Dois níveis, conforme o risco do endpoint:
  * limite padrão (dependência global): ex. 120 req/min por IP;
  * limite estrito de autenticação, em três baldes independentes (login / MFA / token M2M):
      - por CONTA + IP (5/min): frea força bruta vinda de uma origem. Chave composta de
        propósito: um atacante que só conhece o e-mail NÃO consegue esgotar a cota do usuário
        legítimo em outro IP (evita DoS por bloqueio de conta);
      - por IP (20/min): frea credential stuffing (muitas contas, um IP) sem punir uma
        recepção inteira que sai por um único NAT;
      - por CONTA, qualquer IP (15/min): teto para força bruta distribuída em vários IPs.

Limitação conhecida (documentada no relatório): o estado é em memória do
processo. Com várias réplicas, o contador deveria viver em Redis / API gateway.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from core.audit import audit, fingerprint
from core.config import get_settings


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int) -> int | None:
        """Registra uma requisição. Retorna segundos até liberar se excedeu."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] >= window:
                bucket.popleft()
            if len(bucket) >= limit:
                return max(1, int(window - (now - bucket[0])) + 1)
            bucket.append(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowRateLimiter()


def client_ip(request: Request) -> str:
    # Sem confiar em X-Forwarded-For (spoofável). Atrás de proxy confiável,
    # configure o servidor ASGI com --proxy-headers e --forwarded-allow-ips.
    return request.client.host if request.client else "unknown"


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Muitas requisições. Tente novamente mais tarde.",
        headers={"Retry-After": str(retry_after)},
    )


async def default_rate_limit(request: Request) -> None:
    s = get_settings()
    retry = limiter.hit(
        f"default:{client_ip(request)}", s.default_rate_limit, s.default_rate_window_seconds
    )
    if retry:
        audit("rate_limit", outcome="denied", scope="default", ip=client_ip(request))
        raise _too_many(retry)


def enforce_auth_rate_limit(request: Request, scope: str, identifier: str) -> None:
    """Limite estrito para login / MFA / token M2M (ver os três baldes no docstring do módulo)."""
    s = get_settings()
    ip = client_ip(request)
    who = fingerprint(identifier)
    buckets = (
        (f"auth:{scope}:acct+ip:{who}:{ip}", s.login_rate_limit),
        (f"auth:{scope}:ip:{ip}", s.login_rate_limit_per_ip),
        (f"auth:{scope}:acct:{who}", s.login_rate_limit_per_account),
    )
    for key, limit in buckets:
        retry = limiter.hit(key, limit, s.login_rate_window_seconds)
        if retry:
            audit("rate_limit", outcome="denied", scope=scope, ip=ip, id=fingerprint(identifier))
            raise _too_many(retry)

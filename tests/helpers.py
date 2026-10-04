"""Funções auxiliares (sem fixtures) usadas pelos testes."""
from datetime import datetime, timedelta


def cpf_check_digits(nine: str) -> str:
    digits = [int(c) for c in nine]
    for _ in range(2):
        total = sum(d * w for d, w in zip(digits, range(len(digits) + 1, 1, -1)))
        digits.append((total * 10 % 11) % 10)
    return "".join(str(d) for d in digits[9:])


def next_slot(days: int = 2, hour: int = 10, minute: int = 0) -> datetime:
    """Próximo dia útil (>= hoje + days) no horário pedido — sempre no futuro."""
    d = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=days)
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return d


import re  # noqa: E402

PASSWORD = "Senha-Forte-12345"


def signin(client, email: str, password: str = PASSWORD):
    return client.post("/user/signin", data={"username": email, "password": password})


def web_login(client, email: str, password: str = PASSWORD, mfa_code: str = ""):
    """Login pela página HTML (com token CSRF), como um navegador faria."""
    page = client.get("/web/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return client.post(
        "/web/login",
        data={"username": email, "password": password, "mfa_code": mfa_code, "csrf_token": csrf},
        follow_redirects=False,
    )

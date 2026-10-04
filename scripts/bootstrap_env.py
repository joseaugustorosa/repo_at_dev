"""Gera um .env LOCAL com segredos aleatórios (Exercício 11).

Uso:  python scripts/bootstrap_env.py
- Nunca sobrescreve um .env existente.
- O segredo do cliente M2M (laboratório) é gravado em evidence/.local/ (0600, fora do git e do
  ZIP); só o HASH bcrypt vai ao .env.
- O .env está no .gitignore e NÃO deve ser incluído no pacote de entrega.
"""
import secrets
import sys
from pathlib import Path

import bcrypt

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / ".env"


def main() -> int:
    if TARGET.exists():
        print(f"{TARGET} já existe — nada foi alterado.", file=sys.stderr)
        return 1
    lab_secret = secrets.token_urlsafe(32)
    lab_hash = bcrypt.hashpw(lab_secret.encode(), bcrypt.gensalt(rounds=12)).decode()
    content = (ROOT / ".env.example").read_text()
    for line_key in ("JWT_SECRET_KEY", "MFA_MASTER_KEY"):
        content = content.replace(f"{line_key}=<gerar-valor-aleatorio>", f"{line_key}={secrets.token_urlsafe(48)}")
    content = content.replace("<hash-bcrypt-gerado-pelo-bootstrap_env.py>", lab_hash)
    TARGET.write_text(content)
    TARGET.chmod(0o600)
    local = ROOT / "evidence" / ".local"
    local.mkdir(parents=True, exist_ok=True)
    secret_file = local / "lab_client_secret.txt"
    secret_file.write_text(lab_secret + "\n")
    secret_file.chmod(0o600)
    print(f".env criado em {TARGET}")
    print(f"Segredo do cliente M2M 'laboratorio-parceiro' gravado em {secret_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

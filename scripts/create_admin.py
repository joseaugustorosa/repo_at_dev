"""Cria o primeiro administrador (não existe auto-cadastro na API).

Uso:  python scripts/create_admin.py "Nome Sobrenome" admin@clinica.com.br
A senha é pedida no terminal (não vai para o histórico do shell). Imprime o URI
de provisionamento TOTP para cadastrar no app autenticador — mostrado só agora.
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlmodel import Session, select  # noqa: E402

from auth import mfa  # noqa: E402
from auth.hash_password import HashPassword  # noqa: E402
from database.connection import engine, init_db  # noqa: E402
from models.users import Role, User, UserCreate  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    name, email = sys.argv[1], sys.argv[2]
    password = getpass.getpass("Senha (mín. 12 caracteres): ")
    data = UserCreate(name=name, email=email, password=password, role=Role.admin)  # valida tudo
    init_db()
    with Session(engine) as session:
        if session.exec(select(User).where(User.email == data.email.lower())).first():
            print("E-mail já cadastrado.", file=sys.stderr)
            return 1
        user = User(name=data.name, email=data.email.lower(), password_hash=HashPassword().create_hash(data.password),
                    role=Role.admin, mfa_seed=mfa.new_seed())
        session.add(user)
        session.commit()
        session.refresh(user)
        print(f"Admin criado (id={user.id}). Cadastre no app autenticador:\n{mfa.provisioning_uri(user)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

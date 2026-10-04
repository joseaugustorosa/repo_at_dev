"""Hash de senhas com bcrypt (Exercício 6). Senha em texto plano jamais é armazenada."""
import bcrypt

from core.config import get_settings


class HashPassword:
    def create_hash(self, password: str) -> str:
        rounds = get_settings().bcrypt_rounds
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds)).decode()

    def verify_hash(self, plain_password: str, hashed_password: str) -> bool:
        try:
            return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
        except ValueError:  # senha > 72 bytes ou hash malformado
            return False

    def burn_cpu(self, plain_password: str) -> None:
        """Gasta o mesmo tempo de uma verificação real quando o usuário não existe,
        para que o tempo de resposta não revele quais e-mails estão cadastrados."""
        self.verify_hash(plain_password, _dummy_hash())


_DUMMY: str | None = None


def _dummy_hash() -> str:
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = HashPassword().create_hash("dummy-password-for-timing")
    return _DUMMY

"""Popula o banco LOCAL com dados fictícios para a demonstração (vídeo / ZAP).

Gera senhas aleatórias e as grava em evidence/.local/demo_credentials.json
(ignorado pelo git e fora do ZIP). Todos os nomes/CPFs são fictícios.
"""
import json
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlmodel import Session, select  # noqa: E402

from auth import mfa  # noqa: E402
from auth.hash_password import HashPassword  # noqa: E402
from database.connection import engine, init_db  # noqa: E402
from models.appointments import Appointment  # noqa: E402
from models.patients import Patient  # noqa: E402
from models.users import Role, User  # noqa: E402

CPFS = ["529.982.247-25", "168.995.350-09", "111.444.777-35", "935.411.347-80"]


def next_workday(days: int, hour: int, minute: int = 0) -> datetime:
    d = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=days)
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return d


def main() -> None:
    init_db()
    hasher = HashPassword()
    creds: dict[str, dict] = {}
    with Session(engine) as s:
        if s.exec(select(User)).first():
            print("Banco já tem usuários — nada a fazer (apague clinica.db para recriar).")
            return
        spec = [("Admin Demo", "admin@demo.clinica.com.br", Role.admin),
                ("Rita Recepcao", "recepcao@demo.clinica.com.br", Role.recepcionista),
                ("Dra Helena Costa", "helena@demo.clinica.com.br", Role.profissional),
                ("Dr Paulo Mendes", "paulo@demo.clinica.com.br", Role.profissional)]
        users = {}
        for name, email, role in spec:
            pwd = secrets.token_urlsafe(14)
            u = User(name=name, email=email, password_hash=hasher.create_hash(pwd), role=role,
                     mfa_seed=mfa.new_seed() if role is Role.admin else None)
            s.add(u)
            s.commit()
            s.refresh(u)
            users[email] = u
            creds[email] = {"password": pwd, "role": role.value, "id": u.id}
            if u.mfa_seed:
                creds[email]["mfa_uri"] = mfa.provisioning_uri(u)
        helena, paulo = users["helena@demo.clinica.com.br"], users["paulo@demo.clinica.com.br"]
        patients = []
        for i, (name, owner) in enumerate([("Maria da Silva", helena), ("Joao Pereira", helena),
                                           ("Ana Beatriz Lima", paulo), ("Carlos Eduardo Rocha", paulo)]):
            p = Patient(name=name, cpf="".join(c for c in CPFS[i] if c.isdigit()), phone=f"1199900000{i}",
                        professional_id=owner.id, created_by_user_id=1)
            s.add(p)
            s.commit()
            s.refresh(p)
            patients.append((p, owner))
        agenda = [(0, 9, "Retorno de exames", "Paciente refere melhora. PA 120/80."),
                  (0, 10, "Consulta de rotina", "Solicitado hemograma completo."),
                  (0, 14, "Avaliacao inicial", "Queixa de cefaleia ha 2 semanas."),
                  (1, 9, "Retorno", None)]
        for (p, owner), (days, hour, reason, notes) in zip(patients, agenda):
            s.add(Appointment(patient_id=p.id, professional_id=owner.id, date_time=next_workday(days + 1, hour),
                              reason=reason, notes=notes, created_by_user_id=owner.id, created_from_ip="10.0.0.5"))
        s.commit()
    out = ROOT / "evidence" / ".local"
    out.mkdir(parents=True, exist_ok=True)
    (out / "demo_credentials.json").write_text(json.dumps(creds, indent=2, ensure_ascii=False))
    (out / "demo_credentials.json").chmod(0o600)
    print(f"Dados de demonstração criados. Credenciais em {out / 'demo_credentials.json'}")


if __name__ == "__main__":
    main()

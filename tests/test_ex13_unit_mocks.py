"""Exercício 13 — testes unitários com mocking: validação de entrada e autorização.

Aqui nada de HTTP nem banco real: as dependências (bcrypt, sessão, relógio, auditoria)
são substituídas por `unittest.mock`, isolando a regra de segurança testada.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from auth import mfa, ownership, rbac
from auth.hash_password import HashPassword
from auth.jwt_handler import InvalidToken, TokenUse, create_token, decode_token
from core.rate_limit import SlidingWindowRateLimiter
from models.appointments import AppointmentCreate, AppointmentUpdate
from models.base import is_valid_cpf
from models.patients import PatientCreate
from models.users import MFAVerifyRequest, Role, UserCreate


def fake_user(role: Role, user_id: int = 1, **kw):
    return SimpleNamespace(id=user_id, role=role, is_active=True, **kw)


def future(minutes_ahead: int = 60 * 24 * 3) -> datetime:
    t = (datetime.now() + timedelta(minutes=minutes_ahead)).replace(second=0, microsecond=0)
    return t.replace(minute=0 if t.minute < 30 else 30)


# ================================ ENTRADA =====================================
class TestEntradaPydantic:
    def test_consulta_valida(self):
        m = AppointmentCreate(patient_id=1, date_time=future(), reason="Retorno", notes="Sem queixas.")
        assert m.patient_id == 1

    @pytest.mark.parametrize("extra", ["professional_id", "status", "id", "is_admin"])
    def test_extra_forbid_em_consulta(self, extra):
        with pytest.raises(ValidationError) as exc:
            AppointmentCreate(patient_id=1, date_time=future(), reason="Retorno", **{extra: 1})
        assert exc.value.errors()[0]["type"] == "extra_forbidden"

    @pytest.mark.parametrize("bad", [
        {"patient_id": 0}, {"patient_id": -3}, {"patient_id": "1 OR 1=1"},
        {"reason": "ab"}, {"reason": "<b>x</b>"}, {"reason": "a" * 121},
        {"notes": "x" * 2001}, {"notes": "<script>"},
    ])
    def test_campos_invalidos_de_consulta(self, bad):
        base = dict(patient_id=1, date_time=future(), reason="Retorno")
        with pytest.raises(ValidationError):
            AppointmentCreate(**{**base, **bad})

    def test_data_no_passado_ou_fora_do_bloco_ou_com_fuso(self):
        base = dict(patient_id=1, reason="Retorno")
        for when in (datetime.now() - timedelta(days=1), future().replace(minute=7), "2030-01-01T10:00:00+03:00"):
            with pytest.raises(ValidationError):
                AppointmentCreate(date_time=when, **base)

    def test_update_nao_tem_campos_de_posse(self):
        assert set(AppointmentUpdate.model_fields) == {"date_time", "reason", "notes", "status"}
        with pytest.raises(ValidationError):
            AppointmentUpdate(professional_id=2)

    @pytest.mark.parametrize("cpf,ok", [
        ("529.982.247-25", True), ("52998224725", True), ("111.111.111-11", False),
        ("123.456.789-00", False), ("", False), ("5299822472", False), ("abc.def.ghi-jk", False),
    ])
    def test_validacao_de_cpf(self, cpf, ok):
        assert is_valid_cpf(cpf) is ok

    def test_senha_acima_de_72_bytes_e_rejeitada(self):
        base = dict(name="Fulano Teste", email="f@clinica.com.br", role=Role.recepcionista)
        with pytest.raises(ValidationError):
            UserCreate(password="á" * 40, **base)  # 80 bytes em UTF-8
        with pytest.raises(ValidationError):
            UserCreate(password="curta", **base)
        assert UserCreate(password="uma-senha-longa-123", **base).role is Role.recepcionista

    def test_paciente_normaliza_cpf_e_valida_telefone(self):
        p = PatientCreate(name="Maria Souza", cpf="529.982.247-25", phone="11999998888", professional_id=2)
        assert p.cpf == "52998224725"
        with pytest.raises(ValidationError):
            PatientCreate(name="Maria Souza", cpf="529.982.247-25", phone="(11) 9999", professional_id=2)

    def test_codigo_mfa_so_aceita_6_digitos(self):
        token = "t" * 30
        assert MFAVerifyRequest(mfa_token=token, code="123456")
        for code in ("12345", "1234567", "abcdef", "12 456"):
            with pytest.raises(ValidationError):
                MFAVerifyRequest(mfa_token=token, code=code)


# =========================== SENHA / JWT / MFA (mocks) =========================
class TestCriptografiaComMocks:
    def test_verify_hash_trata_erro_do_bcrypt_como_falha(self):
        with patch("auth.hash_password.bcrypt.checkpw", side_effect=ValueError("password too long")):
            assert HashPassword().verify_hash("x" * 100, "$2b$12$abc") is False

    def test_login_de_usuario_inexistente_gasta_o_mesmo_custo_de_hash(self):
        """Anti-enumeração por tempo: sem usuário, ainda assim roda uma verificação bcrypt."""
        from auth import service

        session = MagicMock()
        session.exec.return_value.first.return_value = None
        with patch.object(service.hasher, "burn_cpu") as burn, patch.object(service, "audit"):
            assert service.authenticate_user(session, "ninguem@x.com", "qualquer") is None
        burn.assert_called_once_with("qualquer")

    def test_usuario_inativo_nao_autentica_mesmo_com_senha_certa(self):
        from auth import service

        user = fake_user(Role.profissional, password_hash="h")
        user.is_active = False
        session = MagicMock()
        session.exec.return_value.first.return_value = user
        with patch.object(service.hasher, "verify_hash") as verify, \
                patch.object(service.hasher, "burn_cpu") as burn, patch.object(service, "audit"):
            assert service.authenticate_user(session, "x@x.com", "senha") is None
        verify.assert_not_called()  # a senha certa nem chega a ser comparada
        burn.assert_called_once()  # e o custo de tempo continua igual ao de um login normal

    def test_decode_traduz_qualquer_erro_do_pyjwt_em_invalid_token(self):
        for exc in (jwt.ExpiredSignatureError, jwt.InvalidSignatureError, jwt.InvalidAudienceError,
                    jwt.MissingRequiredClaimError("exp")):
            with patch("auth.jwt_handler.jwt.decode", side_effect=exc):
                with pytest.raises(InvalidToken):
                    decode_token("qualquer.token.aqui")

    def test_decode_exige_algoritmo_fixo_e_claims_obrigatorias(self):
        with patch("auth.jwt_handler.jwt.decode", return_value={"token_use": "access"}) as dec:
            decode_token("a.b.c")
        kwargs = dec.call_args.kwargs
        assert kwargs["algorithms"] == ["HS256"]
        assert {"exp", "iss", "aud", "sub", "jti", "token_use"} <= set(kwargs["options"]["require"])

    def test_token_de_tipo_inesperado_e_recusado(self):
        token = create_token(subject="1", token_use=TokenUse.mfa, ttl=timedelta(minutes=1))
        with pytest.raises(InvalidToken):
            decode_token(token, allowed_uses={TokenUse.access})
        assert decode_token(token, allowed_uses={TokenUse.mfa})["sub"] == "1"

    def test_expiracao_com_relogio_controlado(self):
        """O PyJWT lê o relógio via `datetime.now`; congelamos 31 min no futuro."""
        token = create_token(subject="1", token_use=TokenUse.access, ttl=timedelta(minutes=30))
        assert decode_token(token)["sub"] == "1"  # dentro da validade
        with patch("jwt.api_jwt.datetime") as clock:
            clock.now.return_value = datetime.now(timezone.utc) + timedelta(minutes=31)
            with pytest.raises(InvalidToken):
                decode_token(token)

    def test_totp_janela_e_replay_com_relogio_fixo(self):
        user = fake_user(Role.admin, email="a@x.com", mfa_seed=mfa.new_seed(), mfa_last_step=None)
        t0 = 1_900_000_000
        code = mfa._totp(user.mfa_seed).at(t0)
        assert mfa.verify_code(user, code, now=t0) is True
        assert user.mfa_last_step == t0 // 30
        assert mfa.verify_code(user, code, now=t0) is False  # replay
        user.mfa_last_step = None
        assert mfa.verify_code(user, code, now=t0 + 29 * 3) is False  # fora da janela ±1 passo

    def test_totp_sem_semente_nunca_valida(self):
        assert mfa.verify_code(fake_user(Role.admin, mfa_seed=None, mfa_last_step=None), "123456") is False


# ============================ AUTORIZAÇÃO (mocks) ==============================
class TestAutorizacaoComMocks:
    def _request(self):
        return SimpleNamespace(url=SimpleNamespace(path="/user/"), method="GET")

    def test_require_roles_libera_papel_permitido(self):
        checker = rbac.require_roles(Role.admin)
        admin = fake_user(Role.admin)
        assert checker(self._request(), admin) is admin

    @pytest.mark.parametrize("role", [Role.recepcionista, Role.profissional])
    def test_require_roles_nega_e_audita(self, role):
        checker = rbac.require_roles(Role.admin)
        with patch.object(rbac, "audit") as audit, pytest.raises(HTTPException) as exc:
            checker(self._request(), fake_user(role, user_id=7))
        assert exc.value.status_code == 403
        audit.assert_called_once()
        assert audit.call_args.args[0] == "access_denied" and audit.call_args.kwargs["user_id"] == 7

    def test_require_scopes_exige_token_m2m_com_o_escopo(self):
        from auth.principal import Principal

        checker = rbac.require_scopes("availability:read")
        req = self._request()
        ok = Principal(token_use=TokenUse.m2m, subject="lab", jti="j", scopes=frozenset({"availability:read"}))
        assert checker(req, ok, None) is ok
        wrong_scope = Principal(token_use=TokenUse.m2m, subject="lab", jti="j", scopes=frozenset({"x"}))
        user_token = Principal(token_use=TokenUse.access, subject="1", jti="j", role=Role.admin,
                               scopes=frozenset({"availability:read"}))  # até com o escopo: não é M2M
        for principal in (wrong_scope, user_token):
            with patch.object(rbac, "audit"), pytest.raises(HTTPException) as exc:
                checker(req, principal, None)
            assert exc.value.status_code == 403
            assert "insufficient_scope" in exc.value.headers["WWW-Authenticate"]

    def test_ownership_registra_tentativa_de_bola_e_responde_404(self):
        session = MagicMock()
        session.exec.return_value.first.return_value = None  # filtro de dono não achou nada
        session.get.return_value = object()  # ...mas o registro EXISTE (é de outro)
        with patch.object(ownership, "audit") as audit, pytest.raises(HTTPException) as exc:
            ownership.get_appointment_or_404(session, fake_user(Role.profissional, 5), 42)
        assert exc.value.status_code == 404
        assert audit.call_args.args[0] == "object_access_denied"
        assert audit.call_args.kwargs["resource_id"] == 42

    def test_ownership_inexistente_responde_404_sem_alarme(self):
        session = MagicMock()
        session.exec.return_value.first.return_value = None
        session.get.return_value = None
        with patch.object(ownership, "audit") as audit, pytest.raises(HTTPException) as exc:
            ownership.get_appointment_or_404(session, fake_user(Role.profissional), 999)
        assert exc.value.status_code == 404
        audit.assert_not_called()

    def test_filtro_sql_de_ownership_por_papel(self):
        from sqlmodel import select

        from models.appointments import Appointment

        base = select(Appointment)
        where = lambda role: str(  # noqa: E731
            ownership.scope_appointments(base, fake_user(role, 9)).compile()
        ).partition("WHERE")[2]
        assert "appointments.professional_id =" in where(Role.profissional)
        assert where(Role.admin) == ""  # admin vê tudo: sem filtro
        assert "false" in where(Role.recepcionista).lower() or "0 = 1" in where(Role.recepcionista)

    def test_rota_criar_consulta_traduz_conflito_de_horario_em_409(self):
        """Chama a função da rota diretamente, com sessão simulada que levanta IntegrityError."""
        from routes.appointments import create_appointment

        doctor = fake_user(Role.profissional, 3)
        session = MagicMock()
        session.exec.return_value.first.return_value = SimpleNamespace(id=10)  # paciente do próprio médico
        session.commit.side_effect = IntegrityError("INSERT", {}, Exception("UNIQUE"))
        body = AppointmentCreate(patient_id=10, date_time=future(), reason="Retorno")
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.1"))
        with pytest.raises(HTTPException) as exc:
            create_appointment(request, body, doctor, session)
        assert exc.value.status_code == 409
        session.rollback.assert_called_once()

    def test_rota_criar_consulta_usa_professional_id_do_token(self):
        from routes.appointments import create_appointment

        doctor = fake_user(Role.profissional, 3)
        session = MagicMock()
        session.exec.return_value.first.return_value = SimpleNamespace(id=10)
        body = AppointmentCreate(patient_id=10, date_time=future(), reason="Retorno")
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.1"))
        with patch("routes.appointments.audit"):
            create_appointment(request, body, doctor, session)
        saved = session.add.call_args.args[0]
        assert saved.professional_id == 3 and saved.created_from_ip == "198.51.100.1"


# ======================= TESTE INICIAL DO EX. 1, AGORA COM MOCKS ===============
class TestEx01ComMocks:
    """O caminho de sucesso do Ex. 1 (criar e listar consultas), sem banco real: a sessão é um MagicMock."""

    def test_criar_e_listar_consulta_com_sessao_simulada(self):
        from models.appointments import AppointmentStatus
        from routes.appointments import create_appointment, read_appointments

        doctor = fake_user(Role.profissional, 3)
        session = MagicMock()
        session.exec.return_value.first.return_value = SimpleNamespace(id=10)  # paciente do próprio médico
        body = AppointmentCreate(patient_id=10, date_time=future(), reason="Retorno", notes="Estável.")
        request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.1"))

        with patch("routes.appointments.audit") as audit:
            created = create_appointment(request, body, doctor, session)
        session.add.assert_called_once()
        session.commit.assert_called_once()
        session.refresh.assert_called_once_with(created)
        assert created.professional_id == 3 and created.patient_id == 10
        assert created.status is AppointmentStatus.agendada
        audit.assert_called_once()
        assert audit.call_args.args[0] == "appointment_created"

        session.exec.return_value.all.return_value = [created]
        listed = read_appointments(None, None, None, 50, 0, doctor, session)
        assert listed == [created]
        executed_sql = str(session.exec.call_args.args[0].compile())
        assert "appointments.professional_id =" in executed_sql  # a listagem já nasce filtrada pelo dono
        assert "LIMIT" in executed_sql

    def test_listagem_do_admin_nao_filtra_por_dono_mas_mantem_limite(self):
        from routes.appointments import read_appointments

        session = MagicMock()
        session.exec.return_value.all.return_value = []
        read_appointments(None, None, None, 20, 0, fake_user(Role.admin, 1), session)
        executed_sql = str(session.exec.call_args.args[0].compile())
        assert "appointments.professional_id =" not in executed_sql and "LIMIT" in executed_sql


# ============================== RATE LIMIT (relógio) ===========================
def test_rate_limiter_janela_deslizante_libera_apos_a_janela():
    limiter = SlidingWindowRateLimiter()
    clock = {"t": 1000.0}
    with patch("core.rate_limit.time.monotonic", side_effect=lambda: clock["t"]):
        assert [limiter.hit("k", 3, 60) for _ in range(3)] == [None, None, None]
        assert limiter.hit("k", 3, 60) is not None  # 4ª tentativa na janela => bloqueada
        assert limiter.hit("outra-chave", 3, 60) is None  # chaves independentes
        clock["t"] += 61
        assert limiter.hit("k", 3, 60) is None  # janela passou => liberada

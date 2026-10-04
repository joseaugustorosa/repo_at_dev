"""Configuração central da aplicação (Exercício 11).

Todos os valores sensíveis vêm do ambiente / arquivo `.env` via BaseSettings.
Nenhuma credencial (URL de banco, chave JWT, segredo de cliente M2M) existe no
código-fonte: os campos obrigatórios não têm valor padrão, então a aplicação
se recusa a subir se o `.env` estiver ausente ou incompleto (fail closed).
"""
from functools import lru_cache

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_env: str = "development"  # development | test | production

    # --- Persistência (sem default: credenciais nunca no código) ---
    database_url: str

    # --- JWT / sessão ---
    jwt_secret_key: SecretStr
    mfa_master_key: SecretStr
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "clinica-api"
    jwt_audience: str = "clinica-api"
    access_token_ttl_minutes: int = 30
    mfa_token_ttl_minutes: int = 5
    m2m_token_ttl_minutes: int = 10
    bcrypt_rounds: int = 12

    # --- Cliente M2M (laboratório parceiro) ---
    lab_client_id: str | None = None
    lab_client_secret_hash: SecretStr | None = None
    lab_allowed_scopes: list[str] = ["availability:read"]

    # --- Rede / abuso ---
    cors_allowed_origins: list[str] = []
    login_rate_limit: int = 5  # tentativas/janela por (conta + IP): barra força bruta de uma origem
    login_rate_limit_per_ip: int = 20  # por IP: barra credential stuffing sem punir NAT de clínica
    login_rate_limit_per_account: int = 15  # por conta, qualquer IP: freia força bruta distribuída
    login_rate_window_seconds: int = 60
    default_rate_limit: int = 120
    default_rate_window_seconds: int = 60

    # --- Web (página da recepção) ---
    cookie_secure: bool = True
    enable_docs: bool = True

    @field_validator("jwt_secret_key", "mfa_master_key")
    @classmethod
    def _strong_key(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("chave precisa ter ao menos 32 caracteres")
        return v

    @field_validator("jwt_algorithm")
    @classmethod
    def _only_hs256(cls, v: str) -> str:
        # Allowlist explícita: impede "none" e confusão HS/RS.
        if v != "HS256":
            raise ValueError("somente HS256 é suportado")
        return v

    @field_validator("cors_allowed_origins")
    @classmethod
    def _no_wildcard(cls, v: list[str]) -> list[str]:
        for origin in v:
            if origin.strip() == "*" or not origin.startswith(("http://", "https://")):
                raise ValueError("CORS: use origens explícitas (esquema://host[:porta]), nunca '*'")
        return v

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        if self.app_env == "production":
            if self.bcrypt_rounds < 12:
                raise ValueError("bcrypt_rounds >= 12 é obrigatório em produção")
            if not self.cookie_secure:
                raise ValueError("cookie_secure=true é obrigatório em produção")
            if self.enable_docs:
                raise ValueError("enable_docs=false é obrigatório em produção")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # campos obrigatórios vêm do ambiente

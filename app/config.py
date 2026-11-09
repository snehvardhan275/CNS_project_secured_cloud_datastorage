from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    app_secret: str = ""
    mongodb_uri: str = ""
    mongodb_database: str = "secure_storage"
    session_ttl_seconds: int = 60 * 60 * 8
    otp_ttl_seconds: int = 60 * 5
    otp_resend_seconds: int = 60
    otp_max_attempts: int = 5
    otp_rate_window_seconds: int = 60 * 15
    otp_rate_max: int = 5
    allowed_origins: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True

    @property
    def production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def cookie_secure(self) -> bool:
        return self.production


@lru_cache
def get_settings() -> Settings:
    return Settings()

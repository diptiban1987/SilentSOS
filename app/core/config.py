"""Central application settings.

All values come from environment variables (12-factor). A `.env` file next to
the backend directory is honoured for local development only — production must
inject real environment variables (docker-compose / systemd).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core -------------------------------------------------------------
    APP_NAME: str = "SilentSOS API"
    APP_VERSION: str = "1.0.0"
    ENV: str = Field(default="dev", pattern="^(dev|prod)$")
    SECRET_KEY: str = Field(
        default="dev-insecure-secret-key-change-me-now-please-0123456789",
        min_length=32,
    )
    DATABASE_URL: str = "sqlite:///./silentsos.db"
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Tokens & lockout ---------------------------------------------------
    ACCESS_TOKEN_MINUTES: int = Field(default=15, ge=1, le=120)
    REFRESH_TOKEN_DAYS: int = Field(default=7, ge=1, le=60)
    LOCKOUT_THRESHOLD: int = Field(default=5, ge=1, le=50)
    LOCKOUT_MINUTES: int = Field(default=15, ge=1, le=1440)

    # --- Rate limiting & body limits ----------------------------------------
    RATE_LIMIT_AUTH_PER_MIN: int = Field(default=10, ge=1, le=10_000)
    RATE_LIMIT_API_PER_MIN: int = Field(default=120, ge=1, le=100_000)
    MAX_BODY_BYTES: int = Field(default=262_144, ge=1024)

    # --- SMS ----------------------------------------------------------------
    SMS_PROVIDER: str = Field(default="sim", pattern="^(sim|fast2sms|twilio)$")
    FAST2SMS_API_KEY: str = ""
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_FROM_NUMBER: str = ""
    SMS_WEBHOOK_SECRET: str = "dev-sms-webhook-secret"

    # --- MQTT ---------------------------------------------------------------
    MQTT_ENABLED: bool = False
    MQTT_HOST: str = "localhost"
    MQTT_PORT: int = Field(default=1883, ge=1, le=65535)
    MQTT_USERNAME: str = ""
    MQTT_PASSWORD: str = ""

    # --- First-boot admin bootstrap ------------------------------------------
    SEED_ADMIN_EMAIL: str = "admin@silentsos.local"
    SEED_ADMIN_PASSWORD: str = ""

    @field_validator("DATABASE_URL")
    @classmethod
    def _validate_db_url(cls, v: str) -> str:
        allowed = ("sqlite:///", "postgresql://", "postgresql+psycopg2://")
        if not v.startswith(allowed):
            raise ValueError(
                "DATABASE_URL must be sqlite, postgresql or postgresql+psycopg2"
            )
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_prod(self) -> bool:
        return self.ENV == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()

from typing import Optional, Any
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── Infraestructura ───────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql://ml:ml@ml-db:5432/ml_features"
    REDIS_URL: str = "redis://ml-redis:6379/0"
    APP_ENV: str = "DEVELOPMENT"           # PRODUCTION | DEVELOPMENT
    LOG_LEVEL: str = "INFO"
    MODEL_ARTIFACTS_PATH: str = "/app/model_artifacts"

    # ── Integración GRC ───────────────────────────────────────────────────────
    # Valores requeridos en .env — vacíos por defecto para que no haya nada
    # quemado en el código. El sistema funciona sin ellos en modo DUMMY.
    DEV_GRC_URL: str = ""
    DEV_GRC_API_KEY: str = ""
    DEV_GRC_API_SECRET: str = ""

    # ── Modelo ML ─────────────────────────────────────────────────────────────
    MODEL_MODE: str = "SHADOW"              # DUMMY | SHADOW | LIVE

    # ── Seguridad ─────────────────────────────────────────────────────────────
    # NUNCA poner valores reales aquí — vienen del .env
    SECRET_KEY: str = ""
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: Any = ["http://localhost:3000", "http://localhost:8080"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> list:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        return v

    # ── Circuit Breaker ───────────────────────────────────────────────────────
    CB_FAILURE_THRESHOLD: int = 5
    CB_RECOVERY_TIMEOUT_S: int = 60

    # ── MLOps ────────────────────────────────────────────────────────────────
    SHAP_TIMEOUT_S: int = 30
    RETENTION_DAYS: int = 90

    # ── Threat Intelligence (opcional) ───────────────────────────────────────
    ABUSEIPDB_API_KEY: str = ""            # vacío = deshabilitado

    # ── Ingestión Kafka (opcional) ───────────────────────────────────────────
    KAFKA_BROKER_URL: Optional[str] = None
    KAFKA_INGEST_TOPIC: str = "sentinel.ingest"

    @model_validator(mode='after')
    def validate_secrets(self):
        if self.APP_ENV == "PRODUCTION":
            if not self.SECRET_KEY or not self.JWT_SECRET_KEY:
                raise ValueError("🚨 FATAL: SECRET_KEY y JWT_SECRET_KEY son requeridos y no pueden estar vacíos en PRODUCTION mode.")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


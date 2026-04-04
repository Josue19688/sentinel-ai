from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://ml:ml@ml-db:5432/ml_features"
    REDIS_URL: str = "redis://ml-redis:6379/0"
    APP_ENV: str = "DEVELOPMENT"           # PRODUCTION | DEVELOPMENT
    DEV_GRC_URL: str = "http://host.docker.internal:8000"
    DEV_GRC_API_KEY: str = "grc_4f3c8d55112e3853ba633e9960dfa98b"
    DEV_GRC_API_SECRET: str = "N4ZSmO9tkFSQZ5sL2XY2-GPozCOjClRHcrCKFAHoUh0"
    MODEL_MODE: str = "LIVE"               # DUMMY | SHADOW | LIVE
    SECRET_KEY: str = "dev-secret"
    LOG_LEVEL: str = "INFO"
    SHAP_TIMEOUT_S: int = 30
    CB_FAILURE_THRESHOLD: int = 5           # Circuit Breaker: fallos antes de OPEN
    CB_RECOVERY_TIMEOUT_S: int = 60         # Segundos antes de OPEN → HALF_OPEN
    RETENTION_DAYS: int = 90
    MODEL_ARTIFACTS_PATH: str = "/app/model_artifacts"
    ABUSEIPDB_API_KEY: str = ""             # vacío = deshabilitado; configurar en .env para producción
    
    # Ingestión (Capa 1)
    KAFKA_BROKER_URL: Optional[str] = None
    KAFKA_INGEST_TOPIC: str = "sentinel.ingest"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

settings = Settings()

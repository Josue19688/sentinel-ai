from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://ml:ml@localhost:5432/ml_features"
    REDIS_URL: str = "redis://localhost:6379/0"
    MODEL_MODE: str = "DUMMY"               # DUMMY | SHADOW | LIVE
    SECRET_KEY: str = "dev-secret"
    LOG_LEVEL: str = "INFO"
    SHAP_TIMEOUT_S: int = 30
    CB_FAILURE_THRESHOLD: int = 5           # Circuit Breaker: fallos antes de OPEN
    CB_RECOVERY_TIMEOUT_S: int = 60         # Segundos antes de OPEN → HALF_OPEN
    RETENTION_DAYS: int = 90
    MODEL_ARTIFACTS_PATH: str = "/app/model_artifacts"
    ABUSEIPDB_API_KEY: str = ""             # vacío = deshabilitado; configurar en .env para producción

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

settings = Settings()

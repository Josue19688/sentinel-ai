"""
Registry de modelos — versiones activas y health check.
Usa la tabla model_registry en DB para trazabilidad completa (ISO 42001).
"""
import os, logging
from dataclasses import dataclass
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ModelInfo:
    version:       str
    artifact_path: str


async def get_active_model() -> Optional[ModelInfo]:
    base = settings.MODEL_ARTIFACTS_PATH
    if not os.path.exists(base):
        return None
    versions = sorted([d for d in os.listdir(base) if os.path.isdir(f"{base}/{d}")])
    if not versions:
        return None
    latest = versions[-1]
    return ModelInfo(version=latest, artifact_path=f"{base}/{latest}")


async def register_model_version(
    version:      str,
    f1_score:     float,
    artifact_path: str,
    sha256:       str,
) -> None:
    """
    Registra una nueva versión de modelo en la tabla model_registry.
    Marca la versión anterior como inactiva.
    Cumple ISO 42001: trazabilidad de qué modelo tomó qué decisión y cuándo.
    """
    from app.db import get_db_conn
    async with get_db_conn() as conn:
        async with conn.transaction():
            # Desactivar versión activa anterior
            await conn.execute(
                "UPDATE model_registry SET is_active = FALSE WHERE is_active = TRUE"
            )
            # Registrar la nueva versión como activa
            await conn.execute("""
                INSERT INTO model_registry
                    (version, algorithm, f1_score, artifact_path, is_active)
                VALUES ($1, 'IsolationForest', $2, $3, TRUE)
            """, version, f1_score, artifact_path)

    logger.info(
        f"Model registered: {version} | F1={f1_score:.3f} | "
        f"SHA256={sha256[:16]}... | Path={artifact_path}"
    )


async def get_model_health() -> dict:
    model = await get_active_model()
    from app.drift.psi_monitor import check_circuit_breaker
    cb = await check_circuit_breaker()

    if not model:
        return {
            "status":          "NO_MODEL",
            "message":         "Sin modelo entrenado. Ejecutar: python -m app.models.trainer --mode synthetic",
            "circuit_breaker": cb.state
        }

    # Leer métricas desde model_registry si están disponibles
    registry_info = await _get_registry_metrics(model.version)

    return {
        "status":          "OK",
        "model_version":   model.version,
        "artifact_path":   model.artifact_path,
        "circuit_breaker": cb.state,
        **registry_info
    }


async def _get_registry_metrics(version: str) -> dict:
    """Lee métricas de entrenamiento desde model_registry para el health check."""
    try:
        from app.db import get_db_conn
        async with get_db_conn() as conn:
            row = await conn.fetchrow(
                "SELECT f1_score, algorithm, trained_at FROM model_registry WHERE version=$1",
                version
            )
        if row:
            return {
                "f1_score":   row["f1_score"],
                "algorithm":  row["algorithm"],
                "trained_at": row["trained_at"].isoformat() if row["trained_at"] else None,
            }
    except Exception as e:
        logger.warning(f"No se pudo leer model_registry: {e}")
    return {}

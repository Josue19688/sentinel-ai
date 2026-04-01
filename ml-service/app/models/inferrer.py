"""
Inferrer — Motor de inferencia <50ms
Incluye: normalización, predicción, correlación multi-activo, circuit breaker.
"""
import pickle, hashlib, os, time, logging, numpy as np
from typing import Optional
from pydantic import BaseModel
from app.config import settings
from app.sentinel_v2.normalizer.universal import normalize
from app.db import get_db_conn

logger = logging.getLogger(__name__)
FEATURES = ["severity_score", "asset_value", "timestamp_delta"]

_model_cache = {"model": None, "scaler": None, "version": None}


class InferenceResult(BaseModel):
    recommendation_id: Optional[str] = None
    anomaly_score: float
    aro_suggested: float
    confidence: float
    model_version: Optional[str] = None
    model_mode: str
    lateral_movement_detected: bool
    explanation_pending: bool


def _load_model():
    """Carga el modelo activo desde disco con verificación de integridad."""
    path = _get_active_artifact_path()
    if not path:
        return None, None, None

    pkl_path = f"{path}/model.pkl"
    sha_path = f"{path}/model.sha256"

    # MLSecOps: verificar hash antes de cargar
    with open(pkl_path, "rb") as f:
        content = f.read()
    actual_hash = hashlib.sha256(content).hexdigest()

    with open(sha_path) as f:
        expected_hash = f.read().strip()

    if actual_hash != expected_hash:
        logger.error(f"Model integrity check FAILED — possible tampering!")
        raise RuntimeError("Model artifact hash mismatch")

    artifacts = pickle.loads(content)
    version = os.path.basename(path)
    logger.info(f"Model loaded: {version}")
    return artifacts["model"], artifacts["scaler"], version


def _get_active_artifact_path() -> Optional[str]:
    base = settings.MODEL_ARTIFACTS_PATH
    if not os.path.exists(base):
        return None
    versions = sorted([d for d in os.listdir(base) if os.path.isdir(f"{base}/{d}")])
    return f"{base}/{versions[-1]}" if versions else None


class DotDict(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

async def run_inference(raw: dict, client_id: str) -> InferenceResult:
    # 1. Compatibilidad: Gateway v2 (enriched dict) vs direct ingestion
    if "features_vector" in raw and "asset_id" in raw:
        event = DotDict(raw)
    else:
        event = DotDict(normalize(raw))

    # 2. Modo DUMMY — solo valida conectividad
    if settings.MODEL_MODE == "DUMMY":
        rec_id = await _save_recommendation(event, 0.5, 0.5, 0.5, "dummy", client_id)
        return InferenceResult(
            recommendation_id=rec_id, anomaly_score=0.5,
            aro_suggested=0.5, confidence=0.5,
            model_version="dummy", model_mode="DUMMY",
            lateral_movement_detected=False, explanation_pending=False
        )

    # 3. Cargar modelo (con cache)
    global _model_cache
    if _model_cache["model"] is None:
        _model_cache["model"], _model_cache["scaler"], _model_cache["version"] = _load_model()

    if _model_cache["model"] is None:
        # Fallback ISO 27005 determinístico
        score = event.severity_score
        return InferenceResult(
            recommendation_id=None, anomaly_score=score,
            aro_suggested=score * 12, confidence=0.6,
            model_version=None, model_mode="FALLBACK_ISO27005",
            lateral_movement_detected=False, explanation_pending=False
        )

    # 4. Construir vector y predecir
    vec = np.array([[event.features_vector.get(f, 0.0) for f in FEATURES]])
    vec_scaled = _model_cache["scaler"].transform(vec)
    score_raw = _model_cache["model"].decision_function(vec_scaled)[0]

    # Normalizar score a [0, 1] donde 1 = máxima anomalía
    anomaly_score = float(1 / (1 + np.exp(score_raw)))  # sigmoid inverso
    aro_suggested = anomaly_score * 12   # escala a ocurrencias anuales
    confidence    = min(abs(score_raw) / 0.5, 1.0)

    # 5. Detección de movimiento lateral
    lateral = await _check_lateral_movement(event, client_id)

    # 6. Guardar recomendación
    rec_id = await _save_recommendation(
        event, anomaly_score, aro_suggested, confidence,
        _model_cache["version"], client_id, lateral
    )

    return InferenceResult(
        recommendation_id=rec_id,
        anomaly_score=anomaly_score,
        aro_suggested=aro_suggested,
        confidence=confidence,
        model_version=_model_cache["version"],
        model_mode=settings.MODEL_MODE,
        lateral_movement_detected=lateral,
        explanation_pending=True
    )


async def _check_lateral_movement(event, client_id: str) -> bool:
    """
    Detecta movimiento lateral: anomalía en activo A seguida de
    SSH-success desde el mismo origen hacia activo B en < 5 min.
    """
    if not event.src_ip or event.severity_score < 0.6:
        return False

    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            SELECT id FROM normalized_features
            WHERE client_id = $1
              AND src_ip = $2
              AND asset_id != $3
              AND event_type ILIKE '%ssh%success%'
              AND created_at > NOW() - INTERVAL '5 minutes'
            LIMIT 1
        """, client_id, event.src_ip, event.asset_id)

    return row is not None


async def _save_recommendation(event, score, aro, confidence, version, client_id, lateral=False) -> str:
    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            INSERT INTO ml_recommendations
                (client_id, asset_id, anomaly_score, aro_suggested, confidence,
                 model_version, model_mode, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING')
            RETURNING id::text
        """, client_id, event.asset_id, score, aro, confidence, version, settings.MODEL_MODE)
    return row["id"]

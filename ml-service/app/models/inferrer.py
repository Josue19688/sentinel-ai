"""
Inferrer — Motor de inferencia <50ms
Incluye: normalización, predicción, correlación multi-activo, circuit breaker.

FIX: cache de modelo se invalida automáticamente cuando el trainer
     escribe una nueva versión. Ya no requiere reiniciar el proceso.
"""
import pickle, hashlib, os, time, logging, numpy as np
from typing import Optional
from pydantic import BaseModel
from app.config import settings
from app.normalizer.universal import normalize
from app.db import get_db_conn

logger = logging.getLogger(__name__)
FEATURES = [
    "severity_score", "asset_value", "timestamp_delta",
    "event_type_id", "command_risk", "numeric_anomaly",
    "hour_of_day", "day_of_week", "events_per_minute"
]

_model_cache = {"model": None, "scaler": None, "version": None}


class InferenceResult(BaseModel):
    model_config = {"protected_namespaces": ()}

    recommendation_id: Optional[str] = None
    anomaly_score: float
    aro_suggested: float
    confidence: float
    model_version: Optional[str] = None
    model_mode: str
    lateral_movement_detected: bool
    explanation_pending: bool


def _get_current_version(client_id: str) -> Optional[str]:
    """
    Lee el archivo latest.txt que el trainer escribe al terminar.
    Coste: un open() por petición — despreciable frente a la inferencia.
    Esto permite detectar nuevas versiones sin reiniciar el proceso.
    """
    latest_path = os.path.join(settings.MODEL_ARTIFACTS_PATH, f"{client_id}_latest.txt")
    try:
        with open(latest_path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _load_model(client_id: str):
    """Carga el modelo activo desde disco con verificación de integridad."""
    path = _get_active_artifact_path(client_id)
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


def _get_active_artifact_path(client_id: str) -> Optional[str]:
    """
    Retorna el directorio del modelo más reciente para este client_id.
    Filtra por prefijo para no mezclar modelos de distintos clientes.
    """
    base = settings.MODEL_ARTIFACTS_PATH
    if not os.path.exists(base):
        return None
    versions = sorted([
        d for d in os.listdir(base)
        if os.path.isdir(f"{base}/{d}") and d.startswith(client_id)
    ])
    return f"{base}/{versions[-1]}" if versions else None


class DotDict(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

import asyncio

_model_lock = asyncio.Lock()

async def run_inference(raw: dict, client_id: str) -> InferenceResult:
    # 1. Compatibilidad: Gateway v2 (enriched dict) vs direct ingestion
    if "features_vector" in raw and "asset_id" in raw:
        event = DotDict(raw)
    else:
        event = DotDict(normalize(raw))

    # 2. Modo DUMMY — solo valida conectividad
    if settings.MODEL_MODE == "DUMMY":
        return InferenceResult(
            recommendation_id=None, anomaly_score=0.5,
            aro_suggested=0.5, confidence=0.5,
            model_version="dummy", model_mode="DUMMY",
            lateral_movement_detected=False, explanation_pending=False
        )

    # 3. Cargar modelo con invalidación por versión
    # Se compara la versión en cache contra latest.txt en disco.
    # Si el trainer escribió una versión nueva, se recarga automáticamente.
    global _model_cache
    current_version = _get_current_version(client_id)

    if _model_cache["model"] is None or _model_cache["version"] != current_version:
        async with _model_lock:
            if _model_cache["model"] is None or _model_cache["version"] != current_version:
                logger.info(
                    f"inferrer: recargando modelo — "
                    f"cache={_model_cache['version']} disk={current_version}"
                )
                _model_cache["model"], _model_cache["scaler"], _model_cache["version"] = _load_model(client_id)

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
    import pandas as pd
    from datetime import datetime, timezone
    
    now_dt = datetime.now(timezone.utc)
    
    # Calculate events_per_minute and last_timestamp from DB in a single query
    epm = 0.0
    t_delta = 1.0
    try:
        async with get_db_conn() as conn:
            # Look back up to 24h for the previous event to compute delta
            row = await conn.fetchrow("""
                SELECT 
                    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 minute') as epm_count,
                    MAX(created_at) as last_ts
                FROM normalized_features
                WHERE client_id = $1 AND asset_id = $2
                  AND created_at > NOW() - INTERVAL '24 hours'
            """, client_id, event.asset_id)
            
            if row:
                # 1. Events per minute (normalized 0-1)
                epm = round(min(1.0, row["epm_count"] / 60.0), 4)
                
                # 2. Timestamp delta (normalized using identical log logic as trainer)
                if row["last_ts"]:
                    import math
                    # Convert last_ts to UTC if needed
                    last_dt = row["last_ts"]
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    
                    delta_seconds = (now_dt - last_dt).total_seconds()
                    # Formula identity check: math.log10(delta + 1) / math.log10(3601)
                    t_delta = round(min(1.0, math.log10(max(0, delta_seconds) + 1) / math.log10(3601)), 4)
    except Exception as e:
        logger.warning(f"Error fetching temporal features: {e}")
        pass

    fv = event.features_vector or {}
    vec_dict = {
        "severity_score": float(event.get("severity_score", 0.0)),
        "asset_value": float(fv.get("asset_value", 0.5)),
        "timestamp_delta": float(t_delta),
        "event_type_id": float(fv.get("event_type_id", 0.0)),
        "command_risk": float(fv.get("command_risk", 0.0)),
        "numeric_anomaly": float(fv.get("numeric_anomaly", 0.0)),
        "hour_of_day": round(now_dt.hour / 23.0, 4),
        "day_of_week": round(now_dt.weekday() / 6.0, 4),
        "events_per_minute": epm
    }
    
    vec = pd.DataFrame([[vec_dict[f] for f in FEATURES]], columns=FEATURES)
    vec_scaled = _model_cache["scaler"].transform(vec)
    score_raw = _model_cache["model"].decision_function(vec_scaled)[0]

    # Normalizar score a [0, 1] donde 1 = máxima anomalía
    anomaly_score = float(1 / (1 + np.exp(score_raw)))
    aro_suggested = anomaly_score * 12
    confidence    = min(abs(score_raw) / 0.5, 1.0)

    # 5. Detección de movimiento lateral
    lateral = await _check_lateral_movement(event, client_id)

    # 6. Retornar resultado
    return InferenceResult(
        recommendation_id=None,
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
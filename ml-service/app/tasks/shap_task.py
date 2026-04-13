"""
tasks/shap_task.py
==================
Responsabilidad: Explicabilidad (XAI). Calcula valores SHAP para justificar
las alertas dadas por el modelo de IA ante un auditor.
"""
import json
import logging
import numpy as np
import pandas as pd
from app.celery.celery_app import celery
from app.celery.db         import get_sync_conn, load_model_sync

logger = logging.getLogger(__name__)

FEATURES = [
    "severity_score", "asset_value", "timestamp_delta",
    "event_type_id", "command_risk", "numeric_anomaly",
    "hour_of_day", "day_of_week", "events_per_minute"
]

@celery.task(name="compute_shap", bind=True, max_retries=2)
def compute_shap(self, recommendation_id: str) -> None:
    """Entry point Celery para el cálculo de explicabilidad."""
    try:
        _compute_and_store(recommendation_id)
    except Exception as exc:
        logger.error(f"shap: reintentando por error en {recommendation_id} — {exc}")
        raise self.retry(exc=exc, countdown=10)

def _compute_and_store(recommendation_id: str) -> None:
    """Lógica interna de cálculo SHAP con gestión de pool."""
    with get_sync_conn() as conn:
        with conn.cursor() as cur:
            # 1. Recuperar contexto de la alerta
            cur.execute(
                "SELECT asset_id, anomaly_score FROM ml_recommendations WHERE id=%s::uuid",
                (recommendation_id,)
            )
            rec = cur.fetchone()
            if not rec: return

            asset_id, anomaly_score = rec

            # 2. Contexto histórico
            fv = _get_features(cur, asset_id, anomaly_score)

            # 3. Datos del modelo (Auditoría SHA-256 integrada)
            model, scaler, _ = load_model_sync()
            if model is None: return

            # 4. Cálculo matemático
            vec        = pd.DataFrame([[fv.get(f, 0.0) for f in FEATURES]], columns=FEATURES)
            vec_scaled = scaler.transform(vec)
            shap_dict  = _calculate_shap(model, vec_scaled, fv)

            # 5. Explicación humana
            top_feature = max(shap_dict, key=lambda k: abs(shap_dict[k]))
            explanation = _explain_top_feature(top_feature, fv)
            
            payload = json.dumps({**shap_dict, "explanation": explanation})

            # 6. Persistencia atómica
            cur.execute("""
                UPDATE ml_recommendations 
                SET shap_values = %s::jsonb, shap_ready = TRUE 
                WHERE id = %s::uuid
            """, (payload, recommendation_id))
            conn.commit()
            
            logger.info(f"shap: Explicación generada para {recommendation_id} (Top: {top_feature})")

def _get_features(cur, asset_id: str, anomaly_score: float) -> dict:
    """Busca el último vector de características o retorna fallback."""
    cur.execute("""
        SELECT features_vector FROM normalized_features 
        WHERE asset_id = %s ORDER BY created_at DESC LIMIT 1
    """, (asset_id,))
    row = cur.fetchone()
    if row:
        return row[0] if isinstance(row[0], dict) else json.loads(row[0])
    
    return {"severity_score": anomaly_score, "asset_value": 0.5, "timestamp_delta": 300.0}

def _calculate_shap(model, vec_scaled, fv) -> dict:
    """Calcula valores SHAP reales o aproximación si la librería falta."""
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        val = explainer.shap_values(vec_scaled)
        return {f: float(val[0][i]) for i, f in enumerate(FEATURES)}
    except:
        # Fallback determinista para entornos de baja CPU
        return {
            "severity_score": round((fv.get("severity_score", 0.5) - 0.5) * 0.6, 4),
            "timestamp_delta": round(-fv.get("timestamp_delta", 300) / 10000, 4)
        }

def _explain_top_feature(top_feature, fv) -> str:
    """Convierte la estadística en lenguaje humano."""
    templates = {
        "severity_score": "La severidad del evento superó el patrón histórico.",
        "timestamp_delta": "La ráfaga de eventos fue demasiado rápida.",
        "asset_value": "Involucra un activo de alto impacto financiero."
    }
    return templates.get(top_feature, "Patrón de comportamiento anómalo detectado.")

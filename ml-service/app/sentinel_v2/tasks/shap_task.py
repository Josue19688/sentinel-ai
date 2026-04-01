"""
tasks/shap_task.py
==================
Responsabilidad ÚNICA: calcular y almacenar explicaciones SHAP
para cada recomendación del modelo de IA.

ISO 42001 §7.2 — IA Explicable (XAI):
  Cada decisión del modelo debe estar acompañada de una explicación
  que indique QUÉ features causaron la anomalía y en qué medida.
  SHAP (SHapley Additive exPlanations) cumple este requisito.

Flujo:
  1. Leer la recomendación de PostgreSQL (asset_id, anomaly_score)
  2. Obtener el features_vector más reciente del activo
  3. Cargar el modelo activo con verificación de integridad SHA-256
  4. Calcular SHAP values (o usar aproximación si SHAP no está disponible)
  5. Guardar el resultado en ml_recommendations.shap_values

Reintentos: máximo 2 veces con 10s de espera entre intentos.
"""

import json
import logging
import numpy as np

from app.sentinel_v2.worker.celery_app import celery
from app.sentinel_v2.worker.db         import get_sync_conn, load_model_sync

logger = logging.getLogger(__name__)

FEATURES = ["severity_score", "asset_value", "timestamp_delta"]


# ── Tarea Celery ──────────────────────────────────────────────────────────────

@celery.task(name="compute_shap", bind=True, max_retries=2)
def compute_shap(self, recommendation_id: str) -> None:
    """
    Calcula SHAP para una recomendación específica.
    bind=True permite acceder a self.retry() en caso de error.
    """
    try:
        _compute_and_store(recommendation_id)
    except Exception as exc:
        logger.error(f"shap: fallo en {recommendation_id} — {exc}")
        raise self.retry(exc=exc, countdown=10)


# ── Lógica principal ──────────────────────────────────────────────────────────

def _compute_and_store(recommendation_id: str) -> None:
    conn = get_sync_conn()
    cur  = conn.cursor()
    try:
        # 1. Leer recomendación
        cur.execute(
            "SELECT asset_id, anomaly_score FROM ml_recommendations WHERE id=%s::uuid",
            (recommendation_id,),
        )
        rec = cur.fetchone()
        if not rec:
            logger.warning(f"shap: recomendación {recommendation_id} no encontrada")
            return

        asset_id, anomaly_score = rec

        # 2. Obtener features_vector del activo
        fv = _get_features(cur, asset_id, anomaly_score)

        # 3. Cargar modelo con verificación SHA-256
        model, scaler = load_model_sync()
        if model is None:
            logger.warning(f"shap: no hay modelo disponible para {asset_id}")
            return

        # 4. Calcular SHAP
        vec        = np.array([[fv.get(f, 0.0) for f in FEATURES]])
        vec_scaled = scaler.transform(vec)
        shap_dict  = _calculate_shap(model, vec_scaled, fv)

        # 5. Generar explicación textual
        top_feature = max(shap_dict, key=lambda k: abs(shap_dict[k]))
        explanation = _explain_top_feature(top_feature, fv)
        shap_payload = json.dumps({**shap_dict, "explanation": explanation})

        # 6. Persistir resultado
        cur.execute(
            """
            UPDATE ml_recommendations
            SET shap_values = %s::jsonb, shap_ready = TRUE
            WHERE id = %s::uuid
            """,
            (shap_payload, recommendation_id),
        )
        conn.commit()
        logger.info(f"shap: OK {recommendation_id} — top_feature={top_feature}")

    finally:
        cur.close()
        conn.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_features(cur, asset_id: str, anomaly_score: float) -> dict:
    """Obtiene el último features_vector del activo o construye uno de fallback."""
    cur.execute(
        """
        SELECT features_vector FROM normalized_features
        WHERE asset_id = %s ORDER BY created_at DESC LIMIT 1
        """,
        (asset_id,),
    )
    row = cur.fetchone()

    if row:
        fv = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        return fv

    # Fallback cuando no hay historial del activo
    logger.warning(f"shap: sin features_vector histórico para {asset_id} — usando fallback")
    return {
        "severity_score":  anomaly_score,
        "asset_value":     0.5,
        "timestamp_delta": 300.0,
        "event_type_id":   5.0,
    }


def _calculate_shap(model, vec_scaled: np.ndarray, fv: dict) -> dict:
    """
    Calcula SHAP values usando la librería shap si está disponible.
    Si no, usa una aproximación determinista basada en los valores del vector.
    """
    try:
        import shap
        explainer   = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(vec_scaled)
        return {f: float(shap_values[0][i]) for i, f in enumerate(FEATURES)}

    except Exception as e:
        logger.warning(f"shap: librería no disponible, usando aproximación — {e}")
        return _approximate_shap(fv)


def _approximate_shap(fv: dict) -> dict:
    """
    Aproximación determinista de SHAP cuando la librería no está disponible.
    Los valores son proporcionales a la desviación de cada feature respecto
    a su valor neutral (0.5 para scores, 300 para timestamp_delta).
    """
    return {
        "severity_score":  round((fv.get("severity_score", 0.5) - 0.5) * 0.6, 4),
        "asset_value":     round((fv.get("asset_value", 0.5) - 0.5) * 0.2, 4),
        "timestamp_delta": round(-fv.get("timestamp_delta", 300) / 10_000, 4),
    }


def _explain_top_feature(top_feature: str, fv: dict) -> str:
    """Genera una explicación textual para la feature más influyente."""
    templates = {
        "severity_score": (
            f"Severidad ({fv.get('severity_score', 0):.0%}) superó "
            f"el patrón histórico del activo."
        ),
        "timestamp_delta": (
            f"Frecuencia inusual — {fv.get('timestamp_delta', 0):.0f}s "
            f"desde el evento anterior (baseline: ~300s)."
        ),
        "asset_value": (
            f"Activo de alto valor ({fv.get('asset_value', 0):.0%}) "
            f"involucrado en evento anómalo."
        ),
        "event_type_id": (
            "Tipo de evento no coincide con los patrones históricos del activo."
        ),
    }
    return templates.get(top_feature, "Combinación inusual de factores detectada.")

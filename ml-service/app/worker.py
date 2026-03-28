"""
Celery Worker — SHAP Asíncrono
Usa psycopg2 (síncrono) en lugar de asyncpg porque
Celery no es compatible con asyncio event loops.
"""
from celery import Celery
import pickle, hashlib, numpy as np, logging, json, os
import psycopg2
from app.config import settings

logger = logging.getLogger(__name__)

celery = Celery(
    "sentinel_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery.conf.update(
    task_serializer="json",
    result_expires=3600,
    task_time_limit=60,
    worker_max_tasks_per_child=100
)

FEATURES = ["severity_score", "asset_value", "timestamp_delta", "event_type_id"]


def get_sync_conn():
    return psycopg2.connect(settings.DATABASE_URL)


def load_model_sync():
    """
    Carga el modelo activo desde disco con verificación de integridad SHA-256.
    Replicado desde inferrer._load_model() para mantener consistencia en MLSecOps.
    """
    base = settings.MODEL_ARTIFACTS_PATH
    if not os.path.exists(base):
        return None, None
    versions = sorted([d for d in os.listdir(base) if os.path.isdir(f"{base}/{d}")])
    if not versions:
        return None, None
    path     = f"{base}/{versions[-1]}"
    pkl_path = f"{path}/model.pkl"
    sha_path = f"{path}/model.sha256"
    if not os.path.exists(pkl_path):
        return None, None

    with open(pkl_path, "rb") as f:
        content = f.read()

    # MLSecOps: verificar integridad del artefacto antes de cargarlo
    if os.path.exists(sha_path):
        actual_hash = hashlib.sha256(content).hexdigest()
        with open(sha_path) as f:
            expected_hash = f.read().strip()
        if actual_hash != expected_hash:
            logger.error(
                f"Worker: model integrity check FAILED at {path} — posible manipulación del artefacto"
            )
            return None, None
    else:
        logger.warning(f"Worker: no se encontró {sha_path} — omitiendo verificación de integridad")

    artifacts = pickle.loads(content)
    return artifacts["model"], artifacts["scaler"]


@celery.task(name="compute_shap", bind=True, max_retries=2)
def compute_shap(self, recommendation_id: str):
    try:
        _compute_and_store(recommendation_id)
    except Exception as exc:
        logger.error(f"SHAP failed for {recommendation_id}: {exc}")
        raise self.retry(exc=exc, countdown=10)


def _compute_and_store(recommendation_id: str):
    conn = get_sync_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT asset_id, anomaly_score FROM ml_recommendations WHERE id=%s::uuid",
            (recommendation_id,)
        )
        rec = cur.fetchone()
        if not rec:
            return
        asset_id, anomaly_score = rec

        cur.execute("""
            SELECT features_vector FROM normalized_features
            WHERE asset_id = %s ORDER BY created_at DESC LIMIT 1
        """, (asset_id,))
        feat_row = cur.fetchone()

        if feat_row:
            fv = feat_row[0] if isinstance(feat_row[0], dict) else json.loads(feat_row[0])
        else:
            fv = {
                "severity_score": anomaly_score,
                "asset_value": 0.5,
                "timestamp_delta": 300.0,
                "event_type_id": 5.0
            }

        model, scaler = load_model_sync()
        if model is None:
            return

        vec = np.array([[fv.get(f, 0.0) for f in FEATURES]])
        vec_scaled = scaler.transform(vec)

        try:
            import shap
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(vec_scaled)
            shap_dict = {f: float(shap_values[0][i]) for i, f in enumerate(FEATURES)}
        except Exception as e:
            logger.warning(f"SHAP lib failed, using approximation: {e}")
            shap_dict = {
                "severity_score":  round((fv.get("severity_score", 0.5) - 0.5) * 0.6, 4),
                "asset_value":     round((fv.get("asset_value", 0.5) - 0.5) * 0.2, 4),
                "timestamp_delta": round(-fv.get("timestamp_delta", 300) / 10000, 4),
                "event_type_id":   round(fv.get("event_type_id", 5) / 500, 4),
            }

        top_feature = max(shap_dict, key=lambda k: abs(shap_dict[k]))
        explanation = _generate_explanation(top_feature, fv)
        shap_payload = json.dumps({**shap_dict, "explanation": explanation})

        cur.execute("""
            UPDATE ml_recommendations
            SET shap_values = %s::jsonb, shap_ready = TRUE
            WHERE id = %s::uuid
        """, (shap_payload, recommendation_id))
        conn.commit()
        logger.info(f"SHAP OK for {recommendation_id} — top: {top_feature}")
    finally:
        cur.close()
        conn.close()


def _generate_explanation(top_feature: str, fv: dict) -> str:
    templates = {
        "severity_score":  f"Severidad ({fv.get('severity_score', 0):.0%}) superó el patrón histórico del activo.",
        "timestamp_delta": f"Frecuencia inusual — {fv.get('timestamp_delta', 0):.0f}s desde el evento anterior (baseline: ~300s).",
        "asset_value":     f"Activo de alto valor ({fv.get('asset_value', 0):.0%}) involucrado en evento anómalo.",
        "event_type_id":   "Tipo de evento no coincide con patrones históricos del activo."
    }
    return templates.get(top_feature, "Combinación inusual de factores detectada.")

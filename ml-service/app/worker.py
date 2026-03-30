"""
Celery Worker — SHAP Asíncrono
Usa psycopg2 (síncrono) en lugar de asyncpg porque
Celery no es compatible con asyncio event loops.
"""
from celery import Celery
import pickle, hashlib, numpy as np, logging, json, os
import psycopg2
from app.config import settings
from app.risk_engine import RiskEngine

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

import redis as redis_lib
redis_client = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

# Instancia compartida del motor de riesgo (síncrono — Celery no usa asyncio)
_risk_engine = RiskEngine(db_url=settings.DATABASE_URL)

FEATURES = ["severity_score", "asset_value", "timestamp_delta"]


@celery.task(name="process_ingest_queue")
def process_ingest_queue():
    """
    Recoge logs de la cola de Redis y los inserta en masa en PostgreSQL (Fase 1).
    Optimizado para alto volumen: 1 insert masivo vs N inserts individuales.
    """
    logs = []
    # Sacar hasta 500 logs de la cola
    for _ in range(500):
        log_raw = redis_client.rpop("sentinel:ingest_queue")
        if not log_raw:
            break
        logs.append(json.loads(log_raw))

    if not logs:
        return 0

    conn = get_sync_conn()
    cur = conn.cursor()
    try:
        # Preparar los datos para el insert masivo (copy_from o mogrify)
        # Usaremos string_agg en un solo query para compatibilidad con asyncpg/psycopg2
        records_list = []
        for log in logs:
            # MLSecOps: Extraemos el vector de características (Fase 3)
            # Si no existe, lo reconstruimos para no perder el aprendizaje
            fv = log.get("features_vector")
            if not fv or not isinstance(fv, dict):
                logger.warning(f"Worker: Evento sin features_vector, reconstruyendo para {log.get('event_type')}")
                fv = {
                    "severity_score":  log.get("severity_score", 0.5),
                    "asset_value":     log.get("asset_value", 0.5),
                    "timestamp_delta": 0.0,
                    "event_type_id":   abs(hash(str(log.get("event_type", "unknown")))) % 1000 / 1000
                }
            
            # Aseguramos el event_type_id para compatibilidad con IsolationForest
            if "event_type_id" not in fv:
                fv["event_type_id"] = abs(hash(str(log.get("event_type", "unknown")))) % 1000 / 1000
            
            records_list.append((
                log.get("sentinel_key", "unknown"), # client_id
                log.get("source", "unknown"),       # source_siem (NOT NULL)
                log.get("asset_id", "unknown"),
                log.get("timestamp") or log.get("created_at"), # timestamp_event (NOT NULL)
                log.get("severity_score", 0.5),      # severity_score (NOT NULL)
                log.get("asset_value", 0.5),
                log.get("event_type", "unknown"),
                log.get("src_ip"),
                json.dumps(fv),                      # features_vector (NOT NULL)
                log.get("raw_hash")
            ))

        # Bulk Insert usando execute_values o mogrify
        from psycopg2.extras import execute_values
        query = """
            INSERT INTO normalized_features 
            (client_id, source_siem, asset_id, timestamp_event, severity_score, asset_value, event_type, src_ip, features_vector, raw_hash)
            VALUES %s
        """
        execute_values(cur, query, records_list)
        conn.commit()
        logger.info(f"Fase 1: Persistencia masiva completada — {len(logs)} logs guardados.")
        return len(logs)
    except Exception as e:
        logger.error(f"Fase 1: Error en bulk insert: {e}")
        conn.rollback()
        return 0
    finally:
        cur.close()
        conn.close()


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


@celery.task(name="compute_risk_metrics")
def compute_risk_metrics(client_id: str, asset_id: str, pattern: str, asset_value: float = 0.5):
    """
    Tarea Celery de Fase 2: Recalcula periódicamente o bajo demanda 
    las métricas de riesgo ARO/ALE/EF para un activo específico.
    Utiliza el motor de riesgo cuantitativo.
    """
    try:
        payload = _risk_engine.calculate_risk_for_asset(
            client_id=client_id,
            asset_id=asset_id,
            pattern=pattern,
            window_days=30,
            asset_value=asset_value
        )
        logger.info(f"Risk metrics computed for {asset_id}: ARO={payload['risk_impact_update']['calculated_aro']}")
        return payload
    except Exception as e:
        logger.error(f"Failed to compute risk metrics for {asset_id}: {e}")
        return None

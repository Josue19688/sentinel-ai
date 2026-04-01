"""
tasks/ingest.py
===============
Responsabilidad ÚNICA: recoger logs de Redis, pasarlos por el
pipeline de capas y persistir en PostgreSQL.

Pipeline de 3 capas integrado:
  Redis ingest_queue
       ↓
  [CAPA 1] KafkaFilter  — reglas deterministas, elimina ruido
       ↓ (solo eventos que superan el filtro)
  [CAPA 2] River ML     — detección streaming <1ms por evento
       ↓ (solo eventos sospechosos según River)
  [CAPA 3] IsolationForest — ya en inferrer.py, sin cambios
       ↓
  PostgreSQL normalized_features

Los eventos que River marca como normales (score < ANOMALY_THRESHOLD)
se persisten igualmente para el historial, pero NO se mandan al IF.
Esto reduce la carga del IF en ~80% sin perder datos históricos.
"""

import json
import logging
from psycopg2.extras import execute_values

from app.sentinel_v2.worker.celery_app         import celery
from app.sentinel_v2.worker.db                 import get_sync_conn
from app.sentinel_v2.streaming.river_detector  import get_detector, StreamingResult
from app.sentinel_v2.streaming.kafka_filter    import get_filter

logger = logging.getLogger(__name__)

import redis as redis_lib
from app.config import settings

_redis         = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
BATCH_SIZE     = 500
INGEST_QUEUE   = "sentinel:ingest_queue"
ESCALATE_QUEUE = "sentinel:escalate_queue"   # eventos que van al IF (Capa 3)


@celery.task(name="process_ingest_queue")
def process_ingest_queue() -> dict:
    """
    Lee hasta BATCH_SIZE logs de Redis y los procesa por las 3 capas.
    Retorna métricas del ciclo para observabilidad.
    """
    logs = _drain_queue(BATCH_SIZE)
    if not logs:
        return {"processed": 0, "filtered": 0, "escalated": 0}

    detector = get_detector()
    fltr     = get_filter()

    to_persist = []
    filtered   = 0
    escalated  = 0

    for log in logs:
        # ── Capa 1: filtro de volumen ─────────────────────────────────────
        filter_result = fltr.evaluate(log)
        if not filter_result.passed:
            filtered += 1
            continue

        # ── Capa 2: River ML streaming ────────────────────────────────────
        stream_result: StreamingResult = detector.score(log)

        # Añadir el score de River al log antes de persistir
        log["river_score"]     = stream_result.anomaly_score
        log["river_anomaly"]   = stream_result.is_anomaly
        log["river_learned"]   = stream_result.learned

        # Si River dice que es sospechoso → encolar para el IF (Capa 3)
        if stream_result.should_escalate:
            _redis.lpush(ESCALATE_QUEUE, json.dumps(log))
            escalated += 1
            logger.info(
                f"ingest: escalando al IF — {log.get('asset_id')} "
                f"score={stream_result.anomaly_score:.3f} — {stream_result.reason}"
            )

        to_persist.append(log)

    # Persistir todos los que pasaron el filtro (con su river_score)
    records = [_to_db_record(log) for log in to_persist]
    inserted = _bulk_insert(records)

    metrics = {
        "processed":  len(logs),
        "filtered":   filtered,
        "persisted":  inserted,
        "escalated":  escalated,
        "river_models": detector.model_count(),
    }
    logger.info(f"ingest: ciclo completado — {metrics}")
    return metrics


# ── Helpers privados ──────────────────────────────────────────────────────────

def _drain_queue(max_items: int) -> list[dict]:
    logs = []
    for _ in range(max_items):
        raw = _redis.rpop(INGEST_QUEUE)
        if not raw:
            break
        try:
            logs.append(json.loads(raw))
        except json.JSONDecodeError as e:
            logger.warning(f"ingest: JSON inválido en cola — {e}")
    return logs


def _to_db_record(log: dict) -> tuple:
    fv = log.get("features_vector")
    if not fv or not isinstance(fv, dict):
        fv = {
            "severity_score":  log.get("severity_score", 0.5),
            "asset_value":     log.get("asset_value", 0.5),
            "timestamp_delta": 0.0,
            "event_type_id":   abs(hash(str(log.get("event_type", "unknown")))) % 1000 / 1000,
            "command_risk":    0.0,
            "numeric_anomaly": 0.0,
        }

    if "event_type_id" not in fv:
        fv["event_type_id"] = abs(hash(str(log.get("event_type", "unknown")))) % 1000 / 1000

    # Incluir river_score en el features_vector para el historial
    fv["river_score"] = log.get("river_score", 0.0)

    return (
        log.get("sentinel_key", "unknown"),
        log.get("source", "unknown"),
        log.get("asset_id", "unknown"),
        log.get("timestamp") or log.get("created_at"),
        log.get("severity_score", 0.5),
        log.get("asset_value", 0.5),
        log.get("event_type", "unknown"),
        log.get("src_ip"),
        json.dumps(fv),
        log.get("raw_hash"),
    )


def _bulk_insert(records: list[tuple]) -> int:
    if not records:
        return 0
    query = """
        INSERT INTO normalized_features
            (client_id, source_siem, asset_id, timestamp_event,
             severity_score, asset_value, event_type, src_ip,
             features_vector, raw_hash)
        VALUES %s
    """
    conn = get_sync_conn()
    cur  = conn.cursor()
    try:
        execute_values(cur, query, records)
        conn.commit()
        return len(records)
    except Exception as e:
        logger.error(f"ingest: error en bulk insert — {e}")
        conn.rollback()
        return 0
    finally:
        cur.close()
        conn.close()

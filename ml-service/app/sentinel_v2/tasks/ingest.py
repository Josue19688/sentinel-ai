"""
tasks/ingest.py  [FIXED]
========================
Cambios respecto a la versión anterior:

FIX 1 — Doble filtro eliminado
  Antes: gateway ya aplicó KafkaFilter.send() → evento entra a ingest_queue
         LUEGO ingest.py aplicaba fltr.evaluate() otra vez → segundo filtro
         sobre alertas ya seleccionadas por Wazuh (nivel 5+).
  Ahora: ingest.py NO re-filtra. El evento llegó a la cola porque ya pasó.
         KafkaFilter queda solo en el gateway, donde tiene sentido.

FIX 2 — Forest recibe eventos independientemente de River
  Antes: Forest solo recibía si river_score > 0.45 AND nmap_score > 0.3
         → en warmup (primeros 100 eventos por asset), River devuelve
           score=0.0 siempre → Forest NUNCA recibe nada durante warmup.
  Ahora: lógica de escalación en tres vías:
         A) Nmap determinista puro → escala siempre (no depende de ML)
         B) River score alto (>= ESCALATE_THRESHOLD) → escala
         C) Combined score alto (>= 0.50) → escala
         D) Durante warmup de River: el nmap_detector cubre la brecha

FIX 3 — Visibilidad del estado de Forest
  Añadida métrica 'forest_queue_depth' en el retorno para saber
  cuántos eventos están esperando al IF. Si siempre es 0, el problema
  está en process_escalate_queue, no aquí.
"""

import json
import logging
import time
from psycopg2.extras import execute_values

from app.sentinel_v2.worker.celery_app        import celery
from app.sentinel_v2.worker.db                import get_sync_conn
from app.sentinel_v2.streaming.river_detector import get_detector, StreamingResult
from app.sentinel_v2.streaming.nmap_detector  import NmapDetector

logger = logging.getLogger(__name__)

import redis as redis_lib
from app.config import settings

_redis         = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
_nmap_detector = NmapDetector()
BATCH_SIZE     = 500
INGEST_QUEUE   = "sentinel:ingest_queue"
ESCALATE_QUEUE = "sentinel:escalate_queue"


@celery.task(name="process_ingest_queue")
def process_ingest_queue() -> dict:
    """
    Lee hasta BATCH_SIZE logs de Redis y los procesa.

    Pipeline corregido:
      ingest_queue → River ML + Nmap (paralelo) → Forest si hay señal
                                                 → PostgreSQL siempre

    El KafkaFilter NO se aplica aquí. Ya fue aplicado en el gateway
    antes de que el evento entrara a esta cola.
    """
    logs = _drain_queue(BATCH_SIZE)
    if not logs:
        return {"processed": 0, "escalated": 0, "forest_queue_depth": 0}

    detector   = get_detector()
    to_persist = []
    escalated  = 0

    for log in logs:
        # ── River ML (streaming, evento por evento) ───────────────────────
        stream_result: StreamingResult = detector.score(log)
        river_score = stream_result.anomaly_score
        in_warmup   = stream_result.is_warmup

        # ── Nmap detector (determinista, siempre activo) ──────────────────
        src_ip   = log.get("data", {}).get("srcip") or log.get("src_ip")
        dst_port = log.get("data", {}).get("dstport")
        try:
            ts = float(log.get("timestamp") or log.get("created_at") or time.time())
        except (ValueError, TypeError):
            ts = time.time()

        nmap_meta = {"is_scan": False, "score": 0.0, "unique_ports": 0, "rate_per_min": 0}
        if src_ip and dst_port:
            try:
                nmap_meta = _nmap_detector.observe(src_ip, int(dst_port), ts)
            except (ValueError, TypeError):
                pass

        nmap_score     = nmap_meta.get("score", 0.0)
        nmap_is_scan   = nmap_meta.get("is_scan", False)
        combined_score = (river_score * 0.3) + (nmap_score * 0.7)

        # ── Lógica de escalación (FIX 2) ─────────────────────────────────
        #
        # Tres vías independientes hacia Forest:
        #
        # VÍA A: Nmap detecta escaneo por comportamiento matemático puro.
        #        No depende de River, no depende de warmup.
        #        Si hay 20+ puertos únicos con diversidad > 0.7 → es un scan.
        #
        # VÍA B: River está caliente (>= 100 muestras) y score alto.
        #        El modelo tiene baseline establecido y dice "esto es anómalo".
        #
        # VÍA C: Combined score (nmap+river pesados) supera el umbral.
        #        Captura casos donde ninguno dispara solo pero ambos
        #        ven algo raro al mismo tiempo.
        #
        # Durante warmup de River: solo VÍA A puede escalar.
        # Esto es correcto: durante warmup River no tiene baseline,
        # pero Nmap sí detecta escaneos desde el primer evento.

        via_a = nmap_is_scan
        via_b = (not in_warmup) and (river_score >= 0.45)
        via_c = (not in_warmup) and (combined_score > 0.50)

        should_escalate = via_a or via_b or via_c

        # Log con contexto suficiente para diagnosticar en producción
        if should_escalate:
            via_str = "+".join(filter(None, [
                "nmap_scan" if via_a else "",
                "river"     if via_b else "",
                "combined"  if via_c else "",
            ]))
            logger.warning(
                f"ingest: [ESCALATION] asset={log.get('asset_id')} "
                f"via={via_str} "
                f"river={river_score:.3f} warmup={in_warmup} "
                f"nmap={nmap_score:.3f} scan={nmap_is_scan} "
                f"combined={combined_score:.3f} "
                f"ports={nmap_meta.get('unique_ports')} "
                f"rate={nmap_meta.get('rate_per_min')}/min"
            )
        else:
            logger.debug(
                f"ingest: normal asset={log.get('asset_id')} "
                f"river={river_score:.3f} warmup={in_warmup} "
                f"nmap={nmap_score:.3f}"
            )

        # Anotar el evento con los scores antes de persistir
        log["river_score"]    = river_score
        log["nmap_score"]     = nmap_score
        log["combined_score"] = combined_score
        log["nmap_meta"]      = nmap_meta
        log["river_warmup"]   = in_warmup

        # Encolar para Forest (Capa 3)
        if should_escalate:
            _redis.lpush(ESCALATE_QUEUE, json.dumps(log))
            # Disparar la tarea de Forest inmediatamente si hay eventos
            celery.send_task("process_escalate_queue")
            escalated += 1

        to_persist.append(log)

    # Persistir todo lo que pasó (con scores anotados)
    records  = [_to_db_record(log) for log in to_persist]
    inserted = _bulk_insert(records)

    # FIX 3: reportar la profundidad de la cola de Forest
    forest_depth = _redis.llen(ESCALATE_QUEUE)

    metrics = {
        "processed":         len(logs),
        "persisted":         inserted,
        "escalated":         escalated,
        "river_models":      detector.model_count(),
        "forest_queue_depth": forest_depth,   # si siempre 0 → bug en escalate_task
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

    fv["river_score"]    = log.get("river_score", 0.0)
    fv["nmap_score"]     = log.get("nmap_score", 0.0)
    fv["combined_score"] = log.get("combined_score", 0.0)

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
        ON CONFLICT DO NOTHING
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
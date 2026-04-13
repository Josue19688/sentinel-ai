"""
tasks/ingest.py  [FIXED v2]
============================
FIXES APLICADOS:

FIX 1 — Sin doble registro para eventos escalados.
         Antes: bulk_insert guardaba TODOS los eventos en normalized_features,
         luego escalate_task procesaba los escalados → duplicados.
         Ahora: los eventos que escalan NO van a bulk_insert.
         escalate_task es responsable de su propia persistencia completa.

FIX 2 — raw_hash se propaga al evento antes de escalarlo.
         escalate_task lo usa para deduplicación.

FIX 3 — client_id se valida antes de procesar.
         Si llega vacío/None se loggea como warning — el analista
         puede ver qué fuente no está enviando el campo.

FIX 4 — Separación clara de rutas:
         RUTA A (escala):    → celery escalate_task (persiste en ml_recommendations
                                y en normalized_features vía shap/history)
         RUTA B (no escala): → bulk_insert normalized_features solamente

FIX 5 — normalized_features recibe el pattern_hint correcto del evento,
         no "none" fijo. Antes _to_db_record ignoraba correlation_pattern.
"""

import json
import logging
import time
import hashlib

from app.celery.celery_app         import celery
from app.detection.river_detector  import get_detector, StreamingResult
from app.detection.nmap_detector   import NmapDetector
from app.repositories.features     import bulk_insert_features

logger = logging.getLogger(__name__)

import redis as redis_lib
from app.config import settings

_redis         = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
_nmap_detector = NmapDetector()
BATCH_SIZE     = 500
INGEST_QUEUE   = "sentinel:ingest_queue"


@celery.task(name="process_ingest_queue")
def process_ingest_queue() -> dict:
    """
    Lee hasta BATCH_SIZE logs de Redis y los procesa.

    Pipeline corregido:
      ingest_queue → River ML + Nmap (paralelo)
                   → SI escala: celery escalate_task (NO bulk_insert)
                   → SI NO escala: bulk_insert normalized_features
    """
    logs = _drain_queue(BATCH_SIZE)
    if not logs:
        return {"processed": 0, "escalated": 0, "persisted": 0}

    detector      = get_detector()
    to_persist    = []   # solo los NO escalados
    escalated     = 0
    skipped_no_client = 0

    for log in logs:
        # FIX 3: Validar client_id
        client_id = log.get("client_id") or log.get("sentinel_key")
        if not client_id:
            logger.warning(
                f"ingest: evento sin client_id descartado "
                f"asset={log.get('asset_id')} source={log.get('source')}"
            )
            skipped_no_client += 1
            continue

        # Asegurar que client_id esté en el log para downstream
        log["client_id"] = client_id

        # ── River ML ─────────────────────────────────────────────────────
        stream_result: StreamingResult = detector.score(log)
        river_score = stream_result.anomaly_score
        in_warmup   = stream_result.is_warmup

        # ── Nmap detector ─────────────────────────────────────────────────
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

        nmap_score   = nmap_meta.get("score", 0.0)
        nmap_is_scan = nmap_meta.get("is_scan", False)

        if src_ip and dst_port:
            combined_score = (river_score * 0.4) + (nmap_score * 0.6)
        else:
            combined_score = river_score

        # ── Lógica de escalación ──────────────────────────────────────────
        corr_count   = log.get("correlation_count", 0)
        corr_pattern = log.get("correlation_pattern", "none")

        via_a = nmap_is_scan
        via_b = (not in_warmup) and (river_score >= 0.45)
        via_c = (not in_warmup) and (combined_score > 0.55)
        via_d = (corr_count >= 5) or (corr_pattern in ("brute_force", "brute_force_success"))

        should_escalate = via_a or via_b or via_c or via_d

        # Anotar scores en el evento
        log["river_score"]    = river_score
        log["nmap_score"]     = nmap_score
        log["combined_score"] = combined_score
        log["nmap_meta"]      = nmap_meta
        log["river_warmup"]   = in_warmup

        # FIX 2: Asegurar raw_hash presente para deduplicación downstream
        if not log.get("raw_hash"):
            raw_content = json.dumps({
                "asset_id":   log.get("asset_id"),
                "src_ip":     src_ip,
                "event_type": log.get("event_type"),
                "timestamp":  log.get("timestamp") or log.get("created_at"),
            }, sort_keys=True)
            log["raw_hash"] = hashlib.sha256(raw_content.encode()).hexdigest()

        if should_escalate:
            via_str = "+".join(filter(None, [
                "nmap_scan"   if via_a else "",
                "river"       if via_b else "",
                "combined"    if via_c else "",
                "correlation" if via_d else "",
            ]))
            logger.warning(
                f"ingest: [ESCALATION] asset={log.get('asset_id')} "
                f"client={client_id} via={via_str} "
                f"river={river_score:.3f} nmap={nmap_score:.3f} "
                f"combined={combined_score:.3f} warmup={in_warmup}"
            )
            # FIX 1: NO agregar a to_persist — escalate_task lo persiste
            celery.send_task(
                "process_escalate_queue",
                args=[log],
                queue="celery"
            )
            escalated += 1
        else:
            # Solo los eventos normales van a normalized_features directamente
            to_persist.append(log)

    # Persistir eventos normales (no escalados)
    records  = [_to_db_record(log) for log in to_persist]
    inserted = bulk_insert_features(records) if records else 0

    metrics = {
        "processed":          len(logs),
        "persisted":          inserted,
        "escalated":          escalated,
        "skipped_no_client":  skipped_no_client,
        "river_models":       detector.model_count(),
    }
    logger.info(f"ingest: ciclo completado — {metrics}")
    return metrics


# ── Helpers ───────────────────────────────────────────────────────────────────

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
    """
    Construye la tupla para bulk_insert en normalized_features.
    Solo se llama para eventos que NO escalaron.
    FIX 5: usa correlation_pattern o pattern_hint, no "none" fijo.
    """
    event_type = str(log.get("event_type", "unknown"))
    deterministic_id = (
        int(hashlib.md5(event_type.encode()).hexdigest()[:8], 16) % 1000
    ) / 1000.0

    fv = log.get("features_vector")
    if not fv or not isinstance(fv, dict):
        fv = {
            "severity_score":  log.get("severity_score", 0.5),
            "asset_value":     log.get("asset_value", 0.5),
            "timestamp_delta": 0.0,
            "event_type_id":   deterministic_id,
            "command_risk":    0.0,
            "numeric_anomaly": 0.0,
        }

    if "event_type_id" not in fv:
        fv["event_type_id"] = deterministic_id

    fv["river_score"]    = log.get("river_score", 0.0)
    fv["nmap_score"]     = log.get("nmap_score", 0.0)
    fv["combined_score"] = log.get("combined_score", 0.0)
    fv["pattern"]        = log.get("correlation_pattern") or log.get("pattern_hint", "none")

    return (
        log.get("client_id", "unknown"),
        log.get("source", "unknown"),
        log.get("asset_id", "unknown"),
        log.get("timestamp") or log.get("created_at"),
        log.get("severity_score", 0.5),
        log.get("asset_value", 0.5),
        log.get("event_type", "unknown"),
        log.get("src_ip"),
        json.dumps(fv),
        log.get("correlation_pattern") or log.get("pattern_hint", "none"),  # FIX 5
        log.get("raw_hash"),
    )
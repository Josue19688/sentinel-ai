"""
tasks/escalate_task.py
====================================
Responsabilidad ÚNICA: consumir la escalate_queue y ejecutar
el IsolationForest (Capa 3) sobre eventos que River ML marcó
como sospechosos.

Flujo completo:
  [Capa 1] KafkaFilter     → elimina ruido (gateway.py)
       ↓
  [Capa 2] River ML        → detección streaming (ingest.py)
       ↓ escalate_queue
  [Capa 3] IsolationForest → análisis forense (este archivo)
       ↓
  risk_engine → EF/SLE/ARO/ALE con datos reales del activo
       ↓
  INSERT completo en ml_recommendations
       ↓
  compute_shap → explicación XAI

Cambios respecto a la versión anterior:
  - Se agrega llamada a risk_engine.calculate_risk() DESPUÉS del IF,
    cuando ya tenemos anomaly_score real.
  - El INSERT en ml_recommendations ahora incluye todos los campos:
    scores ML, ISO 27005, snapshot del activo, contexto histórico, src_ip.
  - asset_meta viaja desde el gateway dentro del evento en la cola.
    Si no viene (evento legacy), se usa fallback con valor 0 y
    aro_confidence = 'insufficient_data'.
"""

import json
import logging
import json as _json
from asgiref.sync import async_to_sync

from app.celery.celery_app import celery
from app.config            import settings
from app.celery.db         import get_sync_conn
from app.calculator.risk_engine import calculate_risk

import redis as redis_lib

logger = logging.getLogger(__name__)

_redis         = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
ESCALATE_QUEUE = "sentinel:escalate_queue"


@celery.task(name="process_escalate_queue")
def process_escalate_queue() -> dict | None:
    """
    Lee UN evento de la escalate_queue y lo pasa por:
      1. IsolationForest (run_inference)
      2. risk_engine → EF/SLE/ARO/ALE
      3. INSERT completo en ml_recommendations
      4. compute_shap encolado
    """
    raw = _redis.rpop(ESCALATE_QUEUE)
    if not raw:
        return None

    try:
        event      = json.loads(raw)
        client_id  = event.get("client_id", event.get("sentinel_key", "unknown"))
        asset_id   = event.get("asset_id", "unknown")
        river_score = float(event.get("river_score",    0.0))
        nmap_score  = float(event.get("nmap_score",     0.0))
        combined    = float(event.get("combined_score", 0.0))
        river_warmup = bool(event.get("river_warmup",   False))
        src_ip      = event.get("src_ip")
        pattern     = event.get("pattern_hint", "none")
        event_type  = event.get("event_type",   "unknown")
        asset_meta  = event.get("asset_meta")   # viene del gateway

        logger.info(
            f"escalate: procesando {asset_id} — "
            f"river={river_score:.3f} nmap={nmap_score:.3f} "
            f"pattern={pattern} client={client_id}"
        )

        # ── Capa 3: IsolationForest ──────────────────────────────────────────
        result = async_to_sync(_run_inference_safe)(event, client_id)

        if result is None:
            logger.warning(f"escalate: run_inference retornó None para {asset_id}")
            return None

        anomaly_score = result.anomaly_score

        logger.info(
            f"escalate: IF completado — {asset_id} "
            f"anomaly_score={anomaly_score:.3f} mode={result.model_mode}"
        )

        # ── Cálculo de riesgo ISO 27005 ──────────────────────────────────────
        # Necesitamos conexión síncrona para risk_engine (corre en Celery worker)
        conn = get_sync_conn()
        try:
            if asset_meta:
                risk = calculate_risk(
                    conn          = conn,
                    client_id     = client_id,
                    asset_id      = asset_id,
                    pattern       = pattern,
                    asset_meta    = asset_meta,
                    anomaly_score = anomaly_score,
                )
            else:
                # Evento legacy sin asset_meta — fallback mínimo
                logger.warning(
                    f"escalate: sin asset_meta para {asset_id} — "
                    f"usando fallback de riesgo"
                )
                risk = _risk_fallback(pattern, anomaly_score)

            # ── INSERT completo en ml_recommendations ────────────────────────
            rec_id = _save_recommendation(
                conn         = conn,
                client_id    = client_id,
                asset_id     = asset_id,
                anomaly_score= anomaly_score,
                aro_suggested= result.aro_suggested,
                confidence   = result.confidence,
                model_version= result.model_version,
                model_mode   = result.model_mode,
                lateral      = result.lateral_movement_detected,
                # Nuevos campos
                src_ip       = src_ip,
                pattern      = pattern,
                event_type   = event_type,
                river_score  = river_score,
                nmap_score   = nmap_score,
                combined_score = combined,
                river_warmup = river_warmup,
                risk         = risk,
            )
        finally:
            conn.close()

        if rec_id is None:
            logger.error(f"escalate: INSERT falló para {asset_id}")
            return None

        # ── SHAP ─────────────────────────────────────────────────────────────
        celery.send_task("compute_shap", args=[rec_id])
        logger.info(f"escalate: SHAP encolado para recommendation_id={rec_id}")

        return {
            "asset_id":          asset_id,
            "recommendation_id": rec_id,
            "anomaly_score":     anomaly_score,
            "river_score":       river_score,
            "nmap_score":        nmap_score,
            "aro_suggested":     result.aro_suggested,
            "aro_real":          risk.get("aro"),
            "ale":               risk.get("ale"),
            "aro_confidence":    risk.get("aro_confidence"),
            "confidence":        result.confidence,
            "model_version":     result.model_version,
            "model_mode":        result.model_mode,
            "lateral_movement":  result.lateral_movement_detected,
            "pattern":           pattern,
        }

    except json.JSONDecodeError as e:
        logger.error(f"escalate: JSON inválido en cola — {e}")
        return None
    except Exception as e:
        logger.error(f"escalate: error inesperado — {e}", exc_info=True)
        return None


# ── INSERT ────────────────────────────────────────────────────────────────────

def _save_recommendation(
    conn,
    client_id: str,
    asset_id: str,
    anomaly_score: float,
    aro_suggested: float,
    confidence: float,
    model_version: str | None,
    model_mode: str,
    lateral: bool,
    src_ip: str | None,
    pattern: str,
    event_type: str,
    river_score: float,
    nmap_score: float,
    combined_score: float,
    river_warmup: bool,
    risk: dict,
) -> str | None:
    """
    INSERT completo en ml_recommendations con todos los campos.
    Retorna el UUID generado o None si falló.
    """
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO ml_recommendations (
                client_id,
                asset_id,
                anomaly_score,
                aro_suggested,
                confidence,
                model_version,
                model_mode,
                status,
                src_ip,
                pattern,
                event_type,
                river_score,
                nmap_score,
                combined_score,
                river_warmup,
                ef,
                sle,
                aro,
                ale,
                aro_sample_size,
                aro_period_days,
                aro_confidence,
                valor_activo_snapshot,
                clasificacion_criticidad,
                cia_snapshot,
                impacted_dimensions,
                data_flags,
                attack_count_historical,
                first_occurrence_pattern,
                recurrence_flag
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, 'PENDING',
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s,
                %s::jsonb, %s::jsonb, %s::jsonb,
                %s, %s, %s
            )
            RETURNING id::text
        """, (
            client_id,
            asset_id,
            anomaly_score,
            aro_suggested,
            confidence,
            model_version,
            model_mode,
            src_ip,
            pattern,
            event_type,
            river_score,
            nmap_score,
            combined_score,
            river_warmup,
            risk.get("ef"),
            risk.get("sle"),
            risk.get("aro"),
            risk.get("ale"),
            risk.get("aro_sample_size"),
            risk.get("aro_period_days"),
            risk.get("aro_confidence"),
            risk.get("valor_activo_snapshot"),
            risk.get("clasificacion_criticidad"),
            _json.dumps(risk.get("cia_snapshot") or {}),
            _json.dumps(risk.get("impacted_dimensions") or {}),
            _json.dumps(risk.get("data_flags") or {}),
            risk.get("attack_count_historical", 0),
            risk.get("first_occurrence_pattern", True),
            risk.get("recurrence_flag", False),
        ))

        row = cur.fetchone()
        conn.commit()
        return row[0] if row else None

    except Exception as e:
        logger.error(f"escalate: error en INSERT ml_recommendations — {e}", exc_info=True)
        conn.rollback()
        return None
    finally:
        cur.close()


# ── Fallback cuando no hay asset_meta ────────────────────────────────────────

def _risk_fallback(pattern: str, anomaly_score: float) -> dict:
    """
    Fallback mínimo para eventos legacy sin asset_meta.
    EF real desde la tabla, pero SLE/ALE = 0 porque no tenemos valor_activo.
    ARO = 1.0 con confidence = 'insufficient_data'.
    """
    from app.calculator.risk_engine import PATTERN_EF
    ef = PATTERN_EF.get(pattern, PATTERN_EF["none"])
    return {
        "ef":                     ef,
        "sle":                    0.0,
        "aro":                    1.0,
        "ale":                    0.0,
        "aro_sample_size":        0,
        "aro_period_days":        0,
        "aro_confidence":         "insufficient_data",
        "valor_activo_snapshot":  0.0,
        "clasificacion_criticidad": None,
        "cia_snapshot":           {},
        "impacted_dimensions":    {},
        "data_flags":             {},
        "attack_count_historical": 0,
        "first_occurrence_pattern": True,
        "recurrence_flag":        False,
    }


# ── Helper async ──────────────────────────────────────────────────────────────

async def _run_inference_safe(event: dict, client_id: str):
    try:
        from app.models.inferrer import run_inference
        return await run_inference(event, client_id)
    except Exception as e:
        logger.error(f"escalate: run_inference falló — {e}", exc_info=True)
        return None
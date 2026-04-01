"""
tasks/escalate_task.py
====================================
Responsabilidad ÚNICA: consumir la escalate_queue y ejecutar
el IsolationForest (Capa 3) sobre eventos que River ML marcó
como sospechosos.

Esto cierra el ciclo de las 3 capas:

  [Capa 1] KafkaFilter     → elimina ruido (gateway.py)
       ↓
  [Capa 2] River ML        → detección streaming (ingest.py)
       ↓ escalate_queue
  [Capa 3] IsolationForest → análisis forense (este archivo)
       ↓
  compute_shap → GRC

Por qué asyncio.run() y no get_event_loop():
  Celery corre en un hilo síncrono sin event loop activo.
  get_event_loop() en Python 3.10+ lanza DeprecationWarning
  o RuntimeError bajo carga concurrente.
  asyncio.run() crea un loop limpio, ejecuta la corrutina
  y lo destruye. Es la forma correcta y segura.

Por qué procesar UN evento por tarea (no batch):
  El IsolationForest es el modelo más pesado del stack.
  Procesar en batch dentro de una tarea bloquearía el worker
  durante segundos. Una tarea = un evento = latencia predecible.
  El volumen está controlado porque River ya filtró el 80-90%.
"""

import json
import asyncio
import logging

from app.sentinel_v2.worker.celery_app import celery
from app.config                    import settings
import redis as redis_lib

logger = logging.getLogger(__name__)

_redis         = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
ESCALATE_QUEUE = "sentinel:escalate_queue"


@celery.task(name="process_escalate_queue")
def process_escalate_queue() -> dict | None:
    """
    Lee UN evento de la escalate_queue y lo pasa por el
    IsolationForest + SHAP.

    Retorna el resultado de inferencia o None si la cola está vacía.
    Se llama periódicamente via Celery Beat o se dispara desde ingest.py.
    """
    raw = _redis.rpop(ESCALATE_QUEUE)
    if not raw:
        return None

    try:
        event      = json.loads(raw)
        client_id  = event.get("sentinel_key", "unknown")
        asset_id   = event.get("asset_id", "unknown")
        river_score = event.get("river_score", 0.0)

        logger.info(
            f"escalate: procesando {asset_id} — "
            f"river_score={river_score:.3f} client={client_id}"
        )

        # Ejecutar inferencia async desde contexto síncrono Celery
        result = asyncio.run(_run_inference_safe(event, client_id))

        if result is None:
            return None

        logger.info(
            f"escalate: IF completado — {asset_id} "
            f"anomaly_score={result.anomaly_score:.3f} "
            f"mode={result.model_mode}"
        )

        # Encolar SHAP si hay recomendación pendiente
        if result.recommendation_id:
            celery.send_task(
                "compute_shap",
                args=[result.recommendation_id],
            )
            logger.info(
                f"escalate: SHAP encolado para "
                f"recommendation_id={result.recommendation_id}"
            )

        return {
            "asset_id":         asset_id,
            "anomaly_score":    result.anomaly_score,
            "river_score":      river_score,
            "aro_suggested":    result.aro_suggested,
            "confidence":       result.confidence,
            "model_version":    result.model_version,
            "model_mode":       result.model_mode,
            "lateral_movement": result.lateral_movement_detected,
            "recommendation_id": result.recommendation_id,
        }

    except json.JSONDecodeError as e:
        logger.error(f"escalate: JSON inválido en cola — {e}")
        return None
    except Exception as e:
        logger.error(f"escalate: error inesperado — {e}", exc_info=True)
        return None


# ── Helper async ──────────────────────────────────────────────────────────────

async def _run_inference_safe(event: dict, client_id: str):
    """
    Wrapper que llama a run_inference y captura excepciones
    para que no maten la tarea Celery.
    """
    try:
        from app.models.inferrer import run_inference
        return await run_inference(event, client_id)
    except Exception as e:
        logger.error(f"escalate: run_inference falló — {e}", exc_info=True)
        return None

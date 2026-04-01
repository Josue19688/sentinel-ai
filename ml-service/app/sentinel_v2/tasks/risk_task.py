"""
tasks/risk_task.py
==================
Responsabilidad ÚNICA: tareas Celery de cálculo de riesgo y sandbox forense.

Contiene dos tareas:
  compute_risk_metrics  → recalcula ARO/ALE/EF por activo (ISO 27005)
  process_sandbox_file  → motor forense para el endpoint público /sandbox

Separadas del resto del worker para que puedan escalarse de forma
independiente si el volumen de sandbox crece.
"""

import json
import logging
import redis as redis_lib

from app.config                        import settings
from app.sentinel_v2.worker.celery_app import celery
from app.sentinel_v2.worker.db         import get_sync_conn
from app.sentinel_v2.sandbox.engine    import run as sandbox_run

logger  = logging.getLogger(__name__)
_redis  = redis_lib.from_url(settings.REDIS_URL)

SANDBOX_TTL = 86_400   # 24 horas — cumplimiento GDPR


# ── Tarea: Métricas de riesgo periódicas ──────────────────────────────────────

@celery.task(name="compute_risk_metrics")
def compute_risk_metrics(
    client_id:   str,
    asset_id:    str,
    pattern:     str,
    asset_value: float = 0.5,
) -> dict | None:
    """
    Recalcula ARO, ALE y EF para un activo específico usando datos
    históricos de los últimos 30 días.

    Se invoca desde el gateway cuando se detecta un patrón de riesgo
    medio o alto, para actualizar las métricas en el GRC.
    """
    try:
        risk_engine = get_risk_engine()
        payload = risk_engine.calculate_risk_for_asset(
            client_id   = client_id,
            asset_id    = asset_id,
            pattern     = pattern,
            window_days = 30,
            asset_value = asset_value,
        )
        logger.info(
            f"risk: {asset_id} — "
            f"ARO={payload['risk_impact_update']['calculated_aro']}"
        )
        return payload

    except Exception as e:
        logger.error(f"risk: error para {asset_id} — {e}")
        return None


# ── Tarea: Motor forense sandbox ──────────────────────────────────────────────

@celery.task(name="process_sandbox_file")
def process_sandbox_file(
    session_id:              str,
    payload_str:             str,
    allow_telemetry_training: bool = False,
) -> None:
    """
    Ejecuta el pipeline forense completo sobre un archivo de logs subido
    al endpoint público /sandbox.

    El resultado se guarda en Redis con TTL de 24h (GDPR).
    Si el procesamiento falla, guarda un error estructurado en lugar de
    dejar la sesión colgada indefinidamente.

    allow_telemetry_training:
      Si es True, el usuario consintió que sus datos se usen para
      mejorar el modelo (opt-in explícito en el formulario de subida).
      Por ahora se registra pero no se actúa — base para Fase 4.
    """
    try:
        report = sandbox_run(payload_str)

        if allow_telemetry_training:
            logger.info(
                f"sandbox: sesión {session_id} — "
                f"telemetry_training=True (opt-in registrado)"
            )

        _store_report(session_id, report)
        logger.info(
            f"sandbox: sesión {session_id} completada — "
            f"health={report.get('global_health')} "
            f"assets={report.get('critical_assets_count')}"
        )

    except Exception as exc:
        logger.error(f"sandbox: error fatal en sesión {session_id} — {exc}", exc_info=True)
        _store_report(session_id, {"error": str(exc)})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _store_report(session_id: str, report: dict) -> None:
    """Guarda el reporte en Redis con TTL de 24h."""
    try:
        _redis.setex(
            f"sandbox:{session_id}",
            SANDBOX_TTL,
            json.dumps(report),
        )
    except Exception as e:
        logger.error(f"sandbox: error guardando reporte en Redis — {e}")

"""
repositories/features.py  [FIXED v3]
--------------------------------------
FIXES:

FIX 1 — asset_value se normaliza a 0.0-1.0 antes de insertar.
  El IsolationForest espera features en escala normalizada.
  Antes: insert_escalated_feature recibía asset_value_real=50000.0
  y lo guardaba raw en normalized_features → corrompía el entrenamiento.
  Ahora: si asset_value > 1.0, se normaliza dividiendo por ASSET_VALUE_CEILING.

FIX 2 — ON CONFLICT DO NOTHING en raw_hash para ambas funciones.
  Previene la explosión de filas en normalized_features cuando el mismo
  evento escalado se procesa múltiples veces (reintentos de Celery,
  workers paralelos procesando el mismo batch).

FIX 3 — insert_escalated_feature usa la misma conexión del caller
  (transacción compartida) para atomicidad con ml_recommendations.
"""
import json
import logging
from psycopg2.extras import execute_values
from app.celery.db import get_sync_conn
from app.config import settings

logger = logging.getLogger(__name__)

# Ceiling para normalizar asset_value a rango 0.0-1.0
# Debe coincidir con el valor usado en el trainer (ml_trainer.py)
_ASSET_VALUE_CEILING = float(getattr(settings, "ASSET_VALUE_CEILING", 100_000) or 100_000)


def _normalize_asset_value(raw_value: float) -> float:
    """
    Convierte valor monetario del activo a rango [0.0, 1.0].
    El IsolationForest y HST esperan features normalizados.
    Si ya está normalizado (≤ 1.0), lo devuelve sin cambios.
    """
    if raw_value <= 0:
        return 0.0
    if raw_value <= 1.0:
        return round(raw_value, 4)
    return round(min(raw_value / _ASSET_VALUE_CEILING, 1.0), 4)


def bulk_insert_features(records: list[tuple]) -> int:
    """
    Inserta eventos normales (no escalados) en normalized_features.
    Solo se llama para eventos que NO escalaron (ingest.py ruta B).
    """
    if not records:
        return 0

    query = """
        INSERT INTO normalized_features
            (client_id, source_siem, asset_id, timestamp_event,
             severity_score, asset_value, event_type, src_ip, victim_ip,
             features_vector, pattern_hint, raw_hash)
        VALUES %s
        ON CONFLICT (raw_hash, created_at) WHERE raw_hash IS NOT NULL
        DO NOTHING
    """

    with get_sync_conn() as conn:
        with conn.cursor() as cur:
            try:
                # Normalizar asset_value en cada record antes de insertar
                normalized_records = []
                for rec in records:
                    rec_list = list(rec)
                    # asset_value está en índice 5 en la tupla de _to_db_record
                    if len(rec_list) > 5 and rec_list[5] is not None:
                        rec_list[5] = _normalize_asset_value(float(rec_list[5]))
                    normalized_records.append(tuple(rec_list))

                execute_values(cur, query, normalized_records)
                conn.commit()
                return len(records)
            except Exception as e:
                logger.error(f"features repo: fallo en bulk insert — {e}")
                conn.rollback()
                return 0


def insert_escalated_feature(
    conn,
    client_id:      str,
    asset_id:       str,
    event_type:     str,
    src_ip:         str | None,
    victim_ip:      str | None,
    severity_score: float,
    asset_value:    float,        # puede llegar como valor raw ($50,000) o normalizado
    features_vector: dict,
    pattern_hint:   str,
    raw_hash:       str | None,
    timestamp_event = None,
    source_siem:    str = "unknown",
) -> bool:
    """
    Inserta UN evento escalado en normalized_features.
    Llamado desde escalate_task dentro de la misma transacción que
    ml_recommendations para atomicidad.

    FIX 1: Normaliza asset_value antes de insertar.
    FIX 2: ON CONFLICT DO NOTHING previene duplicados por reintentos.
    """
    # Normalizar asset_value si viene como valor monetario raw
    normalized_av = _normalize_asset_value(float(asset_value))

    # Asegurar que asset_value en features_vector también esté normalizado
    if features_vector.get("asset_value", 0) > 1.0:
        features_vector = {
            **features_vector,
            "asset_value": normalized_av,
        }

    with conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO normalized_features
                    (client_id, source_siem, asset_id, timestamp_event,
                     severity_score, asset_value, event_type, src_ip, victim_ip,
                     features_vector, pattern_hint, raw_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                ON CONFLICT (raw_hash, created_at) WHERE raw_hash IS NOT NULL
                DO NOTHING
            """, (
                client_id,
                source_siem,
                asset_id,
                timestamp_event,
                float(severity_score),
                normalized_av,
                event_type,
                src_ip,
                victim_ip,
                json.dumps(features_vector),
                pattern_hint,
                raw_hash,
            ))
            return True
        except Exception as e:
            logger.error(
                f"features repo: fallo en insert_escalated_feature "
                f"asset={asset_id} — {e}"
            )
            return False
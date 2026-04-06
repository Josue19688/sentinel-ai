"""
repositories/features.py
--------------------------
Acceso a datos para la tabla normalized_features.
Responsabilidad unica: persistir eventos procesados por el pipeline ML.
Usa psycopg2 sincrono (requerido por Celery workers que no pueden usar asyncio).
"""
import json
import logging
from psycopg2.extras import execute_values
from app.celery.db import get_sync_conn

logger = logging.getLogger(__name__)


def bulk_insert_features(records: list[tuple]) -> int:
    """
    Inserta multiples feature-records en un solo round-trip con ON CONFLICT DO NOTHING.
    Retorna el numero de registros insertados, o 0 si fallo.
    """
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
        logger.error(f"features repo: error en bulk insert — {e}")
        conn.rollback()
        return 0
    finally:
        cur.close()
        conn.close()
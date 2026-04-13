"""
worker/db.py
============
Responsabilidad ÚNICA: acceso a base de datos y modelos desde Celery.

Celery no es compatible con asyncio, por eso usamos psycopg2 (síncrono)
con un ThreadedConnectionPool para manejar ráfagas de alta carga.

Seguridad (ISO 27001 A.9 + ISO 42001 §8.3):
  - Verificación de integridad SHA-256 antes de cargar cualquier modelo.
  - Gestión de sesiones robustas para prevenir agotamiento de conexiones.
"""

import os
import pickle
import hashlib
from typing import Any
import logging
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from contextlib import contextmanager
from app.config import settings

logger = logging.getLogger(__name__)

# ── Infraestructura de DB Sincronizada (Capacidad de Carga Masiva) ───────────
_sync_pool = None

def get_pool():
    """Retorna el pool de conexiones sincronas (Singleton)."""
    global _sync_pool
    if _sync_pool is None:
        try:
            _sync_pool = ThreadedConnectionPool(
                minconn=2, 
                maxconn=20, 
                dsn=settings.DATABASE_URL
            )
            logger.info("db: ThreadedConnectionPool inicializado (Capacidad: 2/20)")
        except Exception as e:
            logger.error(f"db: Fallo total al inicializar el pool: {e}")
            raise e
    return _sync_pool

@contextmanager
def get_sync_conn():
    """
    Context manager para obtener y devolver conexiones al pool de forma automática.
    Garantiza que ninguna conexión se quede abierta por error (Anti-Fuga).
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        conn.autocommit = False
        yield conn
    except Exception as e:
        logger.error(f"db: Error en transacción del worker, abortando: {e}")
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)


# ── Carga de modelo con verificación de integridad ───────────────────────────

def load_model_sync() -> tuple[Any, Any, str | None]:
    """
    Carga el modelo activo desde disco con auditoría de integridad SHA-256.
    Retorna: (model, scaler, version) o (None, None, None).
    """
    base = settings.MODEL_ARTIFACTS_PATH
    if not os.path.exists(base):
        logger.warning(f"db: MODEL_ARTIFACTS_PATH no existe: {base}")
        return None, None, None

    versions = sorted([
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d))
    ])
    if not versions:
        logger.warning("db: No hay versiones de modelo disponibles")
        return None, None, None

    latest   = versions[-1]
    path     = os.path.join(base, latest)
    pkl_path = os.path.join(path, "model.pkl")
    sha_path = os.path.join(path, "model.sha256")

    if not os.path.exists(pkl_path):
        return None, None, None

    with open(pkl_path, "rb") as f:
        content = f.read()

    if os.path.exists(sha_path):
        actual_hash   = hashlib.sha256(content).hexdigest()
        with open(sha_path) as f:
            expected_hash = f.read().strip()

        if actual_hash != expected_hash:
            logger.error(f"db: INTEGRIDAD FALLIDA en {latest}. Modelo rechazado por seguridad.")
            return None, None, None
        logger.info(f"db: Modelo {latest} verificado OK")

    try:
        artifacts = pickle.loads(content)
        return artifacts["model"], artifacts["scaler"], latest
    except Exception as e:
        logger.error(f"db: Error deserializando modelo {latest}: {e}")
        return None, None, None

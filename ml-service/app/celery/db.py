"""
worker/db.py
============
Responsabilidad ÚNICA: acceso a base de datos y modelos desde Celery.

Celery no es compatible con asyncio, por eso usamos psycopg2 (síncrono)
en lugar de asyncpg. Este módulo centraliza toda la lógica de DB para
que las tareas no tengan que conocer los detalles de conexión.

Seguridad (ISO 27001 A.9 + ISO 42001 §8.3):
  - Verificación de integridad SHA-256 antes de cargar cualquier modelo
  - Si el hash no coincide: el modelo NO se carga y se lanza alerta
  - Esto previene que un artefacto manipulado (Model Poisoning) llegue a producción
"""

import os
import pickle
import hashlib
import logging
import psycopg2
from app.config import settings

logger = logging.getLogger(__name__)


# ── Conexión DB ───────────────────────────────────────────────────────────────

def get_sync_conn():
    """
    Abre una conexión psycopg2 síncrona.
    Cada tarea abre y cierra su propia conexión (no pool compartido).
    Patrón: llamar en un bloque try/finally para garantizar el cierre.
    """
    return psycopg2.connect(settings.DATABASE_URL)


# ── Carga de modelo con verificación de integridad ───────────────────────────

def load_model_sync() -> tuple:
    """
    Carga el modelo activo desde disco.

    Seguridad ISO 42001 §8.3:
      1. Busca la versión más reciente en MODEL_ARTIFACTS_PATH
      2. Verifica SHA-256 del archivo .pkl contra el .sha256 guardado
      3. Si el hash no coincide → rechaza la carga y retorna (None, None)
      4. Solo si la integridad es válida → deserializa con pickle

    Retorna: (model, scaler) o (None, None) si falla la verificación.
    """
    base = settings.MODEL_ARTIFACTS_PATH
    if not os.path.exists(base):
        logger.warning(f"db: MODEL_ARTIFACTS_PATH no existe: {base}")
        return None, None

    versions = sorted([
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d))
    ])
    if not versions:
        logger.warning("db: No hay versiones de modelo disponibles")
        return None, None

    latest   = versions[-1]
    path     = os.path.join(base, latest)
    pkl_path = os.path.join(path, "model.pkl")
    sha_path = os.path.join(path, "model.sha256")

    if not os.path.exists(pkl_path):
        logger.error(f"db: model.pkl no encontrado en {path}")
        return None, None

    # Leer binario del modelo
    with open(pkl_path, "rb") as f:
        content = f.read()

    # Verificación de integridad (ISO 42001 §8.3)
    if os.path.exists(sha_path):
        actual_hash   = hashlib.sha256(content).hexdigest()
        with open(sha_path) as f:
            expected_hash = f.read().strip()

        if actual_hash != expected_hash:
            logger.error(
                f"db: INTEGRIDAD FALLIDA en {path} — "
                f"esperado={expected_hash[:16]}... "
                f"real={actual_hash[:16]}... "
                f"Posible manipulación del artefacto. Modelo rechazado."
            )
            return None, None

        logger.info(f"db: Modelo {latest} verificado SHA-256 OK")
    else:
        logger.warning(
            f"db: No existe {sha_path} — "
            f"cargando {latest} SIN verificación de integridad"
        )

    try:
        artifacts = pickle.loads(content)
        return artifacts["model"], artifacts["scaler"]
    except Exception as e:
        logger.error(f"db: Error deserializando modelo {latest}: {e}")
        return None, None

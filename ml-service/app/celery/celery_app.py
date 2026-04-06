"""
worker/celery_app.py
====================
Responsabilidad ÚNICA: crear y configurar la instancia de Celery.

Todas las tareas importan `celery` desde aquí.
Nunca importar Celery desde worker.py directamente.

Seguridad (ISO 27001 A.9):
  - El broker URL viene de settings, nunca hardcodeado
  - task_serializer="json" evita deserialización de objetos arbitrarios (pickle RCE)
  - worker_max_tasks_per_child limita memoria y evita fugas de estado entre tareas
"""

from celery import Celery
from app.config import settings
# ── Instancia Celery ──────────────────────────────────────────────────────────

celery = Celery(
    "sentinel_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery.conf.update(
    task_serializer        = "json",    # Seguridad: nunca pickle en producción
    result_serializer      = "json",
    accept_content         = ["json"],  # Rechazar cualquier otro formato
    result_expires         = 3600,
    task_time_limit        = 60,        # Matar tarea si tarda más de 60s
    task_soft_time_limit   = 50,        # Warning a los 50s
    worker_max_tasks_per_child = 100,   # Evitar memory leaks en workers largos
    task_acks_late         = True,      # Reconocer tarea solo al completar (resiliencia)
    worker_prefetch_multiplier = 1,     # Un mensaje a la vez por worker (fair dispatch)
)

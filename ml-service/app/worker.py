"""
worker.py
=========
Punto de entrada de Celery. Registra todas las tareas.
Este archivo NO contiene lógica — solo imports.

Para arrancar:
  celery -A app.worker worker --loglevel=info --concurrency=2

Tareas registradas:
  process_ingest_queue    → Capa 1+2: filtro + River ML
  process_escalate_queue  → Capa 3: IsolationForest + SHAP (NUEVO)
  compute_shap            → Explicabilidad XAI
  compute_risk_metrics    → ARO/ALE periódico ISO 27005
  process_sandbox_file    → Motor forense sandbox
"""

# ── Importar la instancia Celery (punto de entrada para el CLI) ───────────────
from app.sentinel_v2.worker.celery_app import celery  # noqa: F401

# ── Registrar todas las tareas ────────────────────────────────────────────────
# Celery descubre las tareas por el decorador @celery.task.
# Solo necesitamos importar los módulos para que el decorador se ejecute.

from app.sentinel_v2.tasks.ingest       import process_ingest_queue    # noqa: F401
from app.sentinel_v2.tasks.escalate_task import process_escalate_queue  # noqa: F401
from app.sentinel_v2.tasks.shap_task    import compute_shap            # noqa: F401
from app.sentinel_v2.tasks.risk_task    import (                        # noqa: F401
    compute_risk_metrics,
    process_sandbox_file,
)

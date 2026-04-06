"""
API Routes para Control de Modelos MLOps
-----------------------------------------
Permite a sistemas autorizados (GRC) auditar e invocar reentrenamientos
segun los requerimientos de la ISO 42001 (Ciclo de Vida de IA).
"""
import os, time
from typing import Dict, Any, Annotated
from fastapi import APIRouter, Depends, BackgroundTasks

from app.auth.dependencies import CurrentApiClient, CurrentUser, get_current_identity
from app.models.trainer import ModelTrainer
from app.audit.hash_chain import log_audit_event
from app.config import settings

router = APIRouter(prefix="/mlops", tags=["MLOps ISO 42001"])


async def background_trainer(client_id: str):
    """Tarea asincrona para no bloquear el request con el fit del modelo."""
    trainer = ModelTrainer()
    try:
        t0 = time.time()
        result = await trainer.retrain_model(client_id, days_lookback=30)
        dur = time.time() - t0
        await log_audit_event("ML_RETRAIN_SUCCESS", f"v={result.get('version', '')}", client_id, {
            "duration": dur,
            "hash": result.get("hash_sha256", "N/A"),
            "samples": result.get("samples_processed", 0)
        })
    except Exception as e:
        await log_audit_event("ML_RETRAIN_ERROR", str(e), client_id, {})


@router.post("/retrain", response_model=Dict[str, Any])
async def trigger_retrain(
    background_tasks: BackgroundTasks,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """
    Inicia el bucle de aprendizaje continuo (Drift Adjustment).
    Toda la data de los ultimos 30 dias de la tabla normalizada es recargada.
    """
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    background_tasks.add_task(background_trainer, client_id)
    return {
        "status": "accepted",
        "action": "ml_retrain_queued",
        "timestamp": time.time(),
        "client_id": client_id,
        "message": "Aprendizaje iniciado en background.",
    }


@router.get("/versions", response_model=Dict[str, Any])
async def list_model_versions(
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """Lista las versiones del Isolation Forest disponibles para auditoria."""
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id

    if not os.path.exists(settings.MODEL_ARTIFACTS_PATH):
        return {"versions": []}

    files = [f for f in os.listdir(settings.MODEL_ARTIFACTS_PATH) 
             if f.startswith(client_id) and os.path.isdir(os.path.join(settings.MODEL_ARTIFACTS_PATH, f))]
    files.sort(reverse=True)

    versions = []
    for f in files:
        f_path = os.path.join(settings.MODEL_ARTIFACTS_PATH, f)
        stat = os.stat(f_path)
        versions.append({
            "version": f.replace(f"{client_id}_", "").replace(".joblib", ""),
            "size_bytes": stat.st_size,
            "filename": f,
        })

    return {"client_id": client_id, "versions": versions}

"""
API Routes para Control de Modelos MLOps (Fase 3)
-------------------------------------------------
Permite a sistemas autorizados (GRC) auditar e invocar reentrenamientos 
según los requerimientos de la ISO 42001 (Ciclo de Vida de IA).
"""
import os, time
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from app.auth.hmac_validator import verify_hmac
from app.models.trainer import ModelTrainer
from app.audit.hash_chain import log_audit_event

router = APIRouter(prefix="/mlops", tags=["MLOps ISO 42001"])

async def background_trainer(client_id: str):
    """Tarea asíncrona para no bloquear el request con el fit del modelo."""
    trainer = ModelTrainer()
    try:
        t0 = time.time()
        result = await trainer.retrain_model(client_id, days_lookback=30)
        dur = time.time() - t0
        
        # Guardar en cadena de custodia
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
    client_id: str = Depends(verify_hmac)
):
    """
    Inicia el bucle de aprendizaje continuo (Drift Adjustment).
    Toda la data de los últimos 30 días de la tabla normalizada es recargada.
    """
    # Se encola para evitar timeout de API HTTP en caso de miles de muestras
    background_tasks.add_task(background_trainer, client_id)
    
    return {
        "status": "accepted",
        "action": "ml_retrain_queued",
        "timestamp": time.time(),
        "client_id": client_id,
        "message": "Aprendizaje iniciado en background."
    }

@router.get("/versions", response_model=Dict[str, Any])
async def list_model_versions(
    client_id: str = Depends(verify_hmac)
):
    """Lista las últimas 3 versiones del Isolation Forest para auditoría."""
    from app.config import settings
    import os
    
    artifacts = "/app/model_artifacts"
    if not os.path.exists(artifacts):
        return {"versions": []}
        
    files = [f for f in os.listdir(artifacts) if f.startswith(client_id)]
    files.sort(reverse=True)
    
    versions = []
    for f in files:
        f_path = os.path.join(artifacts, f)
        stat = os.stat(f_path)
        versions.append({
            "version": f.replace(f"{client_id}_", "").replace(".joblib", ""),
            "size_bytes": stat.st_size,
            "filename": f
        })
        
    return {"client_id": client_id, "versions": versions}

"""
Sentinel ML Service — API Principal
Inferencia <50ms · JWT/API-Key Auth · Circuit Breaker · ISO 42001
"""
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from prometheus_fastapi_instrumentator import Instrumentator
import time
import logging

from app.config import settings
from app.db import get_pool
from typing import Annotated
from app.auth.dependencies import CurrentApiClient, CurrentUser, get_current_identity
from app.models.inferrer import run_inference
from app.models.registry import get_active_model
from app.audit.hash_chain import log_audit_event
from app.drift.psi_monitor import check_circuit_breaker, close_circuit, record_failure
from app.gateway.router import router as gateway_router
from app.api.auth_router import router as auth_router
from app.api.keys_router import router as keys_router
from app.api.trainer_router import router as trainer_router
from app.api.assets_router import router as assets_router

from pythonjsonlogger import jsonlogger

log_handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(module)s %(funcName)s %(message)s')
log_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(settings.LOG_LEVEL)
for h in logger.handlers[:]:
    logger.removeHandler(h)
logger.addHandler(log_handler)



@asynccontextmanager
async def lifespan(app: FastAPI):
    await get_pool()
    logger.info(f"Sentinel ML Service starting — MODE: {settings.MODEL_MODE}")
    yield
    logger.info("Sentinel ML Service shutting down")


app = FastAPI(
    title="Sentinel ML Service",
    description="Motor de deteccion de anomalias para GRC · ISO 27001 / 42001",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

app.include_router(gateway_router)
app.include_router(auth_router)
app.include_router(keys_router)
app.include_router(trainer_router)
app.include_router(assets_router)

Instrumentator().instrument(app).expose(app)


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}

@app.get("/health/ready")
async def health_ready(
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)],
):
    cb = await check_circuit_breaker()
    model = await get_active_model()
    return {
        "status": "ok",
        "model_mode": settings.MODEL_MODE,
        "model_version": model.version if model else None,
        "circuit_breaker": cb.state,
        "timestamp": time.time()
    }


@app.get("/health/model")
async def health_model(
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)],
):
    """Estado detallado del modelo — para monitoreo y alertas."""
    from app.models.registry import get_model_health
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await get_model_health(client_id)


from pydantic import BaseModel

class InferPayload(BaseModel):
    id: str | int
    model_config = {"extra": "forbid"}

@app.post("/infer")
async def infer(
    payload: InferPayload,
    request: Request,
    background_tasks: BackgroundTasks,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """
    Endpoint principal de inferencia.
    - Responde en <50ms con anomaly_score
    - Encola SHAP en background (disponible en aprox 30s)
    """
    t0 = time.perf_counter()
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id

    cb = await check_circuit_breaker()
    if cb.state == "OPEN":
        raise HTTPException(503, detail={
            "error": "circuit_breaker_open",
            "fallback": "iso27005_deterministic",
            "message": "ML Service degradado. Usando logica ISO 27005."
        })

    body = payload.model_dump(exclude_unset=True)

    try:
        result = await run_inference(body, client_id)
    except Exception as e:
        await log_audit_event("INFERENCE_ERROR", str(e), client_id, {})
        if cb.state == "HALF_OPEN":
            await record_failure()
        raise HTTPException(500, detail=str(e))

    if cb.state == "HALF_OPEN":
        await close_circuit()

    latency_ms = (time.perf_counter() - t0) * 1000

    if result.recommendation_id:
        from app.tasks.shap_task import compute_shap
        background_tasks.add_task(compute_shap.delay, str(result.recommendation_id))

    await log_audit_event("INFERENCE", result.recommendation_id, client_id, result.dict())

    return JSONResponse(
        content=result.dict(),
        headers={
            "X-Model-Mode": settings.MODEL_MODE,
            "X-Latency-Ms": f"{latency_ms:.1f}",
            "X-Model-Version": result.model_version or "none"
        }
    )


@app.get("/recommendations")
async def list_recommendations(
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)],
    status: str = "PENDING",
    limit: int = 50,
):
    from app.api.recommendations import get_recommendations
    # Extraer ID común para auditoría (usamos user_id para que coincida con la creación)
    actor_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await get_recommendations(actor_id, status, limit)


@app.post("/recommendations/{rec_id}/approve")
async def approve(
    rec_id: str,
    note: str = "",
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    from app.api.recommendations import update_recommendation
    actor_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await update_recommendation(rec_id, actor_id, "APPROVED", note)


@app.post("/recommendations/{rec_id}/reject")
async def reject(
    rec_id: str,
    note: str = "",
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    from app.api.recommendations import update_recommendation
    actor_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id
    return await update_recommendation(rec_id, actor_id, "REJECTED", note)


@app.get("/audit/verify")
async def verify_audit_chain(
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """Verificacion de integridad del Hash Chain — para auditorias ISO 27001."""
    from app.audit.hash_chain import verify_chain
    return await verify_chain()

"""
Sentinel ML Service — API Principal
Inferencia <50ms · HMAC Auth · Circuit Breaker · ISO 42001
"""
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time, os, logging

from app.config import settings
from app.db import get_pool
from app.auth.hmac_validator import verify_hmac
from app.models.inferrer import run_inference
from app.models.registry import get_active_model
from app.audit.hash_chain import log_audit_event
from app.drift.psi_monitor import check_circuit_breaker, close_circuit, record_failure
from app.api.routes import router
from app.gateway.gateway import router as gateway_router

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail-fast: si la DB no está disponible, el servicio no arranca
    await get_pool()
    logger.info(f"Sentinel ML Service starting — MODE: {settings.MODEL_MODE}")
    yield
    logger.info("Sentinel ML Service shutting down")


app = FastAPI(
    title="Sentinel ML Service",
    description="Motor de detección de anomalías para GRC · ISO 27001 / 42001",
    version="1.0.0",
    lifespan=lifespan
)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Permitir requests desde el localhost:8080 del dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(gateway_router)

from app.api.trainer_routes import router as trainer_router
app.include_router(trainer_router)


@app.get("/health")
async def health():
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
async def health_model():
    """Estado detallado del modelo — para monitoreo y alertas."""
    from app.models.registry import get_model_health
    return await get_model_health()


@app.post("/infer")
async def infer(
    request: Request,
    background_tasks: BackgroundTasks,
    client_id: str = Depends(verify_hmac)
):
    """
    Endpoint principal de inferencia.
    - Responde en <50ms con anomaly_score
    - Encola SHAP en background (disponible en ~30s)
    """
    t0 = time.perf_counter()

    # Circuit Breaker check
    cb = await check_circuit_breaker()
    if cb.state == "OPEN":
        raise HTTPException(503, detail={
            "error": "circuit_breaker_open",
            "fallback": "iso27005_deterministic",
            "message": "ML Service degradado. Usando lógica ISO 27005."
        })

    body = await request.json()

    try:
        result = await run_inference(body, client_id)
    except Exception as e:
        await log_audit_event("INFERENCE_ERROR", str(e), client_id, {})
        # Si falla en HALF_OPEN → el sistema no se recuperó, volver a OPEN
        if cb.state == "HALF_OPEN":
            await record_failure()
        raise HTTPException(500, detail=str(e))

    # Inferencia exitosa en HALF_OPEN → sistema recuperado, cerrar Circuit Breaker
    if cb.state == "HALF_OPEN":
        await close_circuit()

    latency_ms = (time.perf_counter() - t0) * 1000

    # SHAP en background — nunca bloquea la respuesta
    if result.recommendation_id:
        from app.worker import compute_shap
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
    client_id: str = Depends(verify_hmac),
    status: str = "PENDING",
    limit: int = 50
):
    from app.api.recommendations import get_recommendations
    return await get_recommendations(client_id, status, limit)


@app.post("/recommendations/{rec_id}/approve")
async def approve(rec_id: str, client_id: str = Depends(verify_hmac), note: str = ""):
    from app.api.recommendations import update_recommendation
    return await update_recommendation(rec_id, client_id, "APPROVED", note)


@app.post("/recommendations/{rec_id}/reject")
async def reject(rec_id: str, client_id: str = Depends(verify_hmac), note: str = ""):
    from app.api.recommendations import update_recommendation
    return await update_recommendation(rec_id, client_id, "REJECTED", note)


@app.get("/audit/verify")
async def verify_audit_chain(client_id: str = Depends(verify_hmac)):
    """Verificación de integridad del Hash Chain — para auditorías ISO 27001."""
    from app.audit.hash_chain import verify_chain
    result = await verify_chain()
    return result


@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    """Status UI simple — sin dependencias externas."""
    from app.dashboard import render_dashboard
    return await render_dashboard()

"""
api/dashboard_router.py
=======================
Endpoints para el Dashboard Ejecutivo y Técnico de Sentinel.
Implementa RBAC y filtros de tiempo dinámicos.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional, Annotated
from datetime import datetime

from app.schemas.dashboard import DashboardStats
from app.repositories.dashboard_repository import DashboardRepository
from app.auth.dependencies import get_current_identity, CurrentUser, CurrentApiClient

router = APIRouter(prefix="/v1/dashboard", tags=["Dashboard"])
repo = DashboardRepository()

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    lookback_days: int = Query(7, ge=1, le=30, description="Dias de historial a consultar"),
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None
):
    """
    Retorna el estado consolidado del sistema para el Dashboard.
    Combina metricas de riesgo, tendencias, correlacion de atacantes
    y KPIs ejecutivos en una sola llamada.
    """
    client_id = identity.id if isinstance(identity, CurrentUser) else identity.user_id

    try:
        summary     = await repo.get_stats_summary(client_id, lookback_days * 24)
        trends      = await repo.get_attack_trends(client_id, lookback_days)
        top_ips     = await repo.get_top_entities(client_id, "src_ip")
        top_assets  = await repo.get_top_entities(client_id, "asset_id")
        explanation = await repo.get_latest_explanation(client_id)

        # Bloques analiticos nuevos (Items 2, 3 y 4 del plan)
        attacker_correlation = await repo.get_attacker_correlation(client_id, lookback_days)
        executive_metrics    = await repo.get_executive_metrics(client_id)
        risk_by_asset        = await repo.get_risk_by_asset(client_id)

        return {
            "summary":               summary,
            "trends":                trends,
            "top_attackers":         top_ips,
            "top_assets":            top_assets,
            "latest_explanation":    explanation,
            "system_status":         "LIVE",
            "attacker_correlation":  attacker_correlation,
            "executive_metrics":     executive_metrics,
            "risk_by_asset":         risk_by_asset,
        }
    except Exception as e:
        import logging
        logging.error(f"Error cargando dashboard: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar estadisticas")

@router.get("/health")
async def get_system_health():
    """Endpoint simplificado para el widget de estado del sistema"""
    from app.models.registry import get_model_health
    return await get_model_health()

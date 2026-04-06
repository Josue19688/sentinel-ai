"""
api/recommendations.py — Servicio de recomendaciones
------------------------------------------------------
Responsabilidad: orquestacion y reglas de negocio.
Las queries van en repositories/recommendations.py.
"""
from fastapi import HTTPException

from app.repositories.recommendations import (
    fetch_recommendations,
    fetch_pending_recommendation,
    set_recommendation_status,
)
from app.audit.hash_chain import log_audit_event


async def get_recommendations(client_id: str, status: str, limit: int) -> list[dict]:
    return await fetch_recommendations(client_id, status, limit)


async def update_recommendation(rec_id: str, client_id: str, action: str, note: str) -> dict:
    pending = await fetch_pending_recommendation(rec_id, client_id)
    if not pending:
        raise HTTPException(404, "Recomendacion no encontrada o ya procesada")

    await set_recommendation_status(rec_id, client_id, action, note)

    await log_audit_event(
        f"RECOMMENDATION_{action}",
        rec_id, client_id,
        {"action": action, "note": note}
    )
    return {"id": rec_id, "status": action, "message": f"Recomendacion {action.lower()} correctamente"}
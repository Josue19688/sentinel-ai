"""
Gestión de recomendaciones — aprobar, rechazar, listar.
"""
import json
from app.db import get_db_conn
from app.audit.hash_chain import log_audit_event
from fastapi import HTTPException


async def get_recommendations(client_id: str, status: str, limit: int):
    async with get_db_conn() as conn:
        rows = await conn.fetch("""
            SELECT id::text, asset_id, anomaly_score, aro_suggested,
                   confidence, model_version, model_mode, status,
                   shap_ready, shap_values, created_at::text
            FROM ml_recommendations
            WHERE client_id = $1 AND status = $2
            ORDER BY created_at DESC
            LIMIT $3
        """, client_id, status.upper(), limit)
    return [dict(r) for r in rows]


async def update_recommendation(rec_id: str, client_id: str, action: str, note: str):
    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            SELECT id FROM ml_recommendations
            WHERE id = $1::uuid AND client_id = $2 AND status = 'PENDING'
        """, rec_id, client_id)

        if not row:
            raise HTTPException(404, "Recomendación no encontrada o ya procesada")

        await conn.execute("""
            UPDATE ml_recommendations
            SET status = $1, reviewed_by = $2, review_note = $3, reviewed_at = NOW()
            WHERE id = $4::uuid
        """, action, client_id, note, rec_id)

    await log_audit_event(
        f"RECOMMENDATION_{action}",
        rec_id, client_id,
        {"action": action, "note": note}
    )
    return {"id": rec_id, "status": action, "message": f"Recomendación {action.lower()} correctamente"}

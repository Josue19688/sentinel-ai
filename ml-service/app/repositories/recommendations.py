"""
repositories/recommendations.py
---------------------------------
Acceso a datos para recomendaciones ML.
Responsabilidad unica: queries a la tabla ml_recommendations.
No contiene logica de negocio ni reglas de validacion.
"""
import json
from app.db import get_db_conn


async def fetch_recommendations(client_id: str, status: str, limit: int) -> list[dict]:
    """
    Lista recomendaciones con todos los campos de riesgo ISO 27005,
    scores ML, snapshot del activo y contexto histórico.
    """
    async with get_db_conn() as conn:
        rows = await conn.fetch("""
            SELECT
                id::text,
                asset_id,
                src_ip,
                pattern,
                event_type,

                -- Scores ML
                anomaly_score,
                river_score,
                nmap_score,
                combined_score,
                river_warmup,

                -- IF / modelo
                aro_suggested,
                confidence,
                model_version,
                model_mode,

                -- ISO 27005
                ef,
                sle,
                aro,
                ale,
                aro_sample_size,
                aro_period_days,
                aro_confidence,

                -- Snapshot activo
                valor_activo_snapshot,
                clasificacion_criticidad,
                cia_snapshot,
                impacted_dimensions,
                data_flags,

                -- Contexto histórico / tendencias
                attack_count_historical,
                first_occurrence_pattern,
                recurrence_flag,

                -- Estado y revisión
                status,
                shap_ready,
                shap_values,
                reviewed_by,
                review_note,
                reviewed_at::text,
                created_at::text
            FROM ml_recommendations
            WHERE client_id = $1
              AND status    = $2
            ORDER BY created_at DESC
            LIMIT $3
        """, client_id, status.upper(), limit)
    return [dict(r) for r in rows]


async def fetch_recommendation_by_id(rec_id: str, client_id: str) -> dict | None:
    """Devuelve una recomendación completa por ID."""
    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            SELECT
                id::text,
                asset_id,
                src_ip,
                pattern,
                event_type,
                anomaly_score,
                river_score,
                nmap_score,
                combined_score,
                river_warmup,
                aro_suggested,
                confidence,
                model_version,
                model_mode,
                ef,
                sle,
                aro,
                ale,
                aro_sample_size,
                aro_period_days,
                aro_confidence,
                valor_activo_snapshot,
                clasificacion_criticidad,
                cia_snapshot,
                impacted_dimensions,
                data_flags,
                attack_count_historical,
                first_occurrence_pattern,
                recurrence_flag,
                status,
                shap_ready,
                shap_values,
                reviewed_by,
                review_note,
                reviewed_at::text,
                created_at::text
            FROM ml_recommendations
            WHERE id = $1::uuid AND client_id = $2
        """, rec_id, client_id)
    return dict(row) if row else None


async def fetch_pending_recommendation(rec_id: str, client_id: str) -> dict | None:
    """Devuelve la recomendacion si existe y esta en estado PENDING."""
    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            SELECT id FROM ml_recommendations
            WHERE id = $1::uuid AND client_id = $2 AND status = 'PENDING'
        """, rec_id, client_id)
    return dict(row) if row else None


async def set_recommendation_status(rec_id: str, client_id: str, action: str, note: str) -> None:
    async with get_db_conn() as conn:
        await conn.execute("""
            UPDATE ml_recommendations
            SET status      = $1,
                reviewed_by = $2,
                review_note = $3,
                reviewed_at = NOW()
            WHERE id = $4::uuid
        """, action, client_id, note, rec_id)


async def fetch_asset_behavior(
    client_id: str,
    asset_id: str,
    limit: int = 50,
) -> list[dict]:
    """
    Historial de incidentes de un activo específico, ordenado cronológicamente.
    Útil para analizar tendencias de comportamiento a futuro.
    Incluye: patrón, scores, riesgo calculado y contexto de cada incidente.
    """
    async with get_db_conn() as conn:
        rows = await conn.fetch("""
            SELECT
                id::text,
                src_ip,
                pattern,
                event_type,
                anomaly_score,
                river_score,
                combined_score,
                ef,
                sle,
                aro,
                ale,
                aro_confidence,
                impacted_dimensions,
                attack_count_historical,
                first_occurrence_pattern,
                recurrence_flag,
                status,
                created_at::text
            FROM ml_recommendations
            WHERE client_id = $1
              AND asset_id  = $2
            ORDER BY created_at DESC
            LIMIT $3
        """, client_id, asset_id, limit)
    return [dict(r) for r in rows]


async def fetch_risk_summary(client_id: str) -> dict:
    """
    Resumen de riesgo agregado por activo para el dashboard.
    Retorna ALE total, ARO promedio, patrón más frecuente y conteo de incidentes.
    """
    async with get_db_conn() as conn:
        rows = await conn.fetch("""
            SELECT
                asset_id,
                COUNT(*)                        AS total_incidents,
                SUM(ale)                        AS total_ale,
                AVG(aro)                        AS avg_aro,
                AVG(anomaly_score)              AS avg_anomaly,
                MAX(created_at)::text           AS last_incident,
                MODE() WITHIN GROUP (
                    ORDER BY pattern
                )                               AS most_frequent_pattern
            FROM ml_recommendations
            WHERE client_id = $1
              AND ale        IS NOT NULL
            GROUP BY asset_id
            ORDER BY total_ale DESC NULLS LAST
        """, client_id)
    return {"assets": [dict(r) for r in rows]}
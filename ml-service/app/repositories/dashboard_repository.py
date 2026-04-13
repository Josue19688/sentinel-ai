"""
repositories/dashboard_repository.py
======================================
Consultas SQL optimizadas para el Dashboard de Sentinel.
Usa agregaciones en DB para minimizar el trafico de red y carga de CPU.
"""
import json
import logging
from typing import List, Optional
from app.db import get_pool

logger = logging.getLogger(__name__)


class DashboardRepository:
    def __init__(self):
        self._pool = None

    async def _get_conn(self):
        from app.db import get_pool
        return await get_pool()

    async def get_stats_summary(self, client_id: str, lookback_hours: int = 24) -> dict:
        """Obtiene metricas agregadas (ARO, ALE, Conteos)."""
        pool = await self._get_conn()
        query = """
            SELECT
                COUNT(*) as total_alerts,
                COUNT(*) FILTER (WHERE anomaly_score >= 0.8) as critical_alerts,
                COUNT(*) FILTER (WHERE anomaly_score >= 0.5 AND anomaly_score < 0.8) as medium_alerts,
                COALESCE(SUM(ale), 0) as ale_impact,
                COALESCE(AVG(anomaly_score), 0) as avg_confidence
            FROM ml_recommendations
            WHERE client_id = $1
              AND created_at >= NOW() - ($2 * INTERVAL '1 hour')
        """
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, client_id, lookback_hours)
            return dict(row) if row else {}

    async def get_attack_trends(self, client_id: str, days: int = 7) -> List[dict]:
        """Obtiene la tendencia de ataques agrupada por horas."""
        pool = await self._get_conn()
        query = """
            SELECT
                date_trunc('hour', created_at)::text as timestamp,
                COUNT(*) as count,
                CASE
                    WHEN AVG(anomaly_score) >= 0.8 THEN 'high'
                    WHEN AVG(anomaly_score) >= 0.5 THEN 'medium'
                    ELSE 'low'
                END as risk_level
            FROM ml_recommendations
            WHERE client_id = $1
              AND created_at >= NOW() - ($2 * INTERVAL '1 day')
            GROUP BY 1
            ORDER BY 1 ASC
        """
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, client_id, days)
            return [dict(r) for r in rows]

    async def get_top_entities(self, client_id: str, field: str = "src_ip", limit: int = 5) -> List[dict]:
        """Identifica los principales atacantes o activos afectados."""
        if field not in ["src_ip", "asset_id"]:
            return []
        pool = await self._get_conn()
        query = f"""
            SELECT {field} as entity, COUNT(*) as count
            FROM ml_recommendations
            WHERE client_id = $1
              AND {field} IS NOT NULL
              AND {field} NOT IN ('127.0.0.1', '::1')
            GROUP BY 1
            ORDER BY 2 DESC
            LIMIT $2
        """
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, client_id, limit)
            return [dict(r) for r in rows]

    async def get_latest_explanation(self, client_id: str) -> Optional[str]:
        """Obtiene la ultima explicacion humana generada por SHAP."""
        pool = await self._get_conn()
        query = """
            SELECT shap_values->>'explanation' as explanation
            FROM ml_recommendations
            WHERE client_id = $1 AND shap_ready = TRUE
            ORDER BY created_at DESC
            LIMIT 1
        """
        async with pool.acquire() as conn:
            val = await conn.fetchval(query, client_id)
            return val

    # ── Item 2: Correlacion de atacantes ─────────────────────────────────────

    async def get_attacker_correlation(self, client_id: str, days: int = 7) -> List[dict]:
        """
        Perfil de cada IP atacante: cuantas maquinas ataco, que tipos de ataque uso,
        cuantos eventos genero, riesgo financiero total y si sigue activa.

        Permite al analista ir directamente al SIEM a buscar esa IP sin correlacionar
        manualmente. Reduce fatiga de alertas y acorta el MTTD.
        """
        pool = await self._get_conn()
        query = """
            SELECT
                r.src_ip                                    AS attacker_ip,
                COUNT(DISTINCT r.asset_id)                  AS machines_targeted,
                COUNT(*)                                    AS total_incidents,
                COALESCE(SUM(r.ale), 0)                     AS total_financial_risk,
                MIN(r.first_seen_at)::text                  AS campaign_start,
                MAX(r.last_seen_at)::text                   AS campaign_last_seen,
                BOOL_OR(r.last_seen_at >= NOW() - INTERVAL '10 minutes')
                                                            AS campaign_active,
                BOOL_OR(r.lateral_movement_detected)        AS lateral_movement_confirmed,
                JSON_AGG(
                    JSON_BUILD_OBJECT(
                        'asset_id',    r.asset_id,
                        'victim_ip',   r.victim_ip,
                        'pattern',     r.pattern,
                        'event_type',  r.event_type,
                        'event_count', r.event_count,
                        'ale',         r.ale,
                        'first_seen',  r.first_seen_at::text,
                        'last_seen',   r.last_seen_at::text,
                        'still_active', (r.last_seen_at >= NOW() - INTERVAL '10 minutes')
                    )
                    ORDER BY r.last_seen_at DESC
                )                                           AS attack_timeline
            FROM ml_recommendations r
            WHERE r.client_id = $1
              AND r.src_ip IS NOT NULL
              AND r.src_ip != '0.0.0.0'
              AND r.created_at >= NOW() - ($2 * INTERVAL '1 day')
            GROUP BY r.src_ip
            ORDER BY machines_targeted DESC, total_financial_risk DESC NULLS LAST
            LIMIT 20
        """
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, client_id, days)
            result = []
            for r in rows:
                row = dict(r)
                timeline_raw = row.get("attack_timeline")
                if isinstance(timeline_raw, str):
                    row["attack_timeline"] = json.loads(timeline_raw)
                elif timeline_raw is None:
                    row["attack_timeline"] = []
                result.append(row)
            return result

    # ── Item 3: Metricas ejecutivas CISO ─────────────────────────────────────

    async def get_executive_metrics(self, client_id: str) -> dict:
        """
        KPIs de seguridad para reportes ejecutivos y postura de seguridad.
        Incluye MTTD, MTTR, riesgo financiero activo y alertas sin atender.
        """
        pool = await self._get_conn()
        query = """
            SELECT
                COUNT(*) FILTER (WHERE anomaly_score >= 0.85)                   AS critical_count,
                COUNT(*) FILTER (WHERE anomaly_score >= 0.65
                                   AND anomaly_score < 0.85)                    AS high_count,
                COUNT(*) FILTER (WHERE anomaly_score >= 0.40
                                   AND anomaly_score < 0.65)                    AS medium_count,
                COUNT(*) FILTER (WHERE anomaly_score < 0.40)                    AS low_count,
                COALESCE(SUM(ale) FILTER (
                    WHERE status IN ('PENDING', 'SHADOW')
                ), 0)                                                            AS total_active_financial_risk,
                COUNT(*) FILTER (
                    WHERE status = 'PENDING'
                      AND anomaly_score >= 0.65
                      AND created_at < NOW() - INTERVAL '24 hours'
                )                                                                AS high_alerts_unattended_24h,
                ROUND(AVG(
                    EXTRACT(EPOCH FROM (created_at - first_seen_at)) / 60.0
                ) FILTER (WHERE first_seen_at IS NOT NULL)::numeric, 1)         AS avg_mttd_minutes,
                ROUND(AVG(
                    EXTRACT(EPOCH FROM (reviewed_at - created_at)) / 60.0
                ) FILTER (WHERE reviewed_at IS NOT NULL)::numeric, 1)           AS avg_mttr_minutes,
                COUNT(DISTINCT src_ip) FILTER (
                    WHERE created_at >= NOW() - INTERVAL '7 days'
                )                                                                AS unique_attackers_7d,
                COUNT(DISTINCT asset_id) FILTER (
                    WHERE created_at >= NOW() - INTERVAL '7 days'
                )                                                                AS assets_affected_7d
            FROM ml_recommendations
            WHERE client_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
        """
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, client_id)
            return dict(row) if row else {}

    # ── Item 4: Riesgo financiero por activo ─────────────────────────────────

    async def get_risk_by_asset(self, client_id: str) -> List[dict]:
        """
        Riesgo acumulado agrupado por activo en los ultimos 30 dias.
        Permite priorizar que activo blindar primero basado en dinero en riesgo.
        """
        pool = await self._get_conn()
        query = """
            SELECT
                asset_id,
                clasificacion_criticidad,
                COUNT(*)                                        AS total_incidents,
                COALESCE(SUM(ale), 0)                           AS total_ale_acumulado,
                COALESCE(MAX(valor_activo_snapshot), 0)         AS valor_activo,
                MAX(peak_anomaly_score)                         AS max_risk_score,
                SUM(event_count)                                AS total_eventos_raw,
                MAX(last_seen_at)::text                         AS ultimo_ataque,
                BOOL_OR(last_seen_at >= NOW() - INTERVAL '10 minutes')
                                                                AS bajo_ataque_ahora,
                ARRAY_AGG(DISTINCT pattern)                     AS patrones_detectados,
                COUNT(DISTINCT src_ip)                          AS atacantes_unicos,
                BOOL_OR(lateral_movement_detected)              AS movimiento_lateral
            FROM ml_recommendations
            WHERE client_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY asset_id, clasificacion_criticidad
            ORDER BY total_ale_acumulado DESC NULLS LAST
        """
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, client_id)
            result = []
            for r in rows:
                row = dict(r)
                if row.get("patrones_detectados") is None:
                    row["patrones_detectados"] = []
                result.append(row)
            return result

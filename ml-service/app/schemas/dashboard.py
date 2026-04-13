"""
schemas/dashboard.py
====================
Modelos Pydantic para la respuesta del dashboard ejecutivo y tecnico.
Cumple con la validacion de tipos para evitar inyecciones y errores de datos.
"""
from pydantic import BaseModel, Field
from typing import List, Optional


class RiskSummary(BaseModel):
    total_alerts: int = Field(..., example=1250)
    critical_alerts: int = Field(..., example=12)
    medium_alerts: int = Field(..., example=45)
    ale_impact: float = Field(..., example=12450.50)
    avg_confidence: float = Field(..., example=0.89)


class AttackTrend(BaseModel):
    timestamp: str
    count: int
    risk_level: str


class TopEntity(BaseModel):
    entity: str
    count: int


# ── Item 2: Correlacion de atacantes ─────────────────────────────────────────

class AttackEvent(BaseModel):
    """Un incidente especifico de un atacante contra una maquina victima."""
    asset_id: str
    victim_ip: Optional[str] = None
    pattern: str
    event_type: str
    event_count: Optional[int] = None
    ale: Optional[float] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    still_active: Optional[bool] = None


class AttackerCorrelation(BaseModel):
    """Perfil completo de un atacante: todas sus victimas y tipos de ataque."""
    attacker_ip: str
    machines_targeted: int
    total_incidents: int
    total_financial_risk: Optional[float] = None
    campaign_start: Optional[str] = None
    campaign_last_seen: Optional[str] = None
    campaign_active: bool = False
    lateral_movement_confirmed: bool = False
    attack_timeline: List[AttackEvent] = []


# ── Item 3: Metricas ejecutivas CISO ─────────────────────────────────────────

class ExecutiveMetrics(BaseModel):
    """KPIs de seguridad para el CISO: MTTD, MTTR y riesgo financiero activo."""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_active_financial_risk: float = 0.0
    high_alerts_unattended_24h: int = 0
    avg_mttd_minutes: Optional[float] = None
    avg_mttr_minutes: Optional[float] = None
    unique_attackers_7d: int = 0
    assets_affected_7d: int = 0


# ── Item 4: Riesgo financiero por activo ─────────────────────────────────────

class AssetRisk(BaseModel):
    """Riesgo acumulado por activo para priorizar remediacion."""
    asset_id: str
    clasificacion_criticidad: Optional[str] = None
    total_incidents: int = 0
    total_ale_acumulado: float = 0.0
    valor_activo: float = 0.0
    max_risk_score: Optional[float] = None
    total_eventos_raw: Optional[int] = None
    ultimo_ataque: Optional[str] = None
    bajo_ataque_ahora: bool = False
    patrones_detectados: List[str] = []
    atacantes_unicos: int = 0
    movimiento_lateral: bool = False


# ── Schema principal del dashboard ───────────────────────────────────────────

class DashboardStats(BaseModel):
    summary: RiskSummary
    trends: List[AttackTrend]
    top_attackers: List[TopEntity]
    top_assets: List[TopEntity]
    latest_explanation: Optional[str] = None
    system_status: str = "LIVE"
    # Bloques analiticos Items 2, 3 y 4
    attacker_correlation: List[AttackerCorrelation] = []
    executive_metrics: Optional[ExecutiveMetrics] = None
    risk_by_asset: List[AssetRisk] = []

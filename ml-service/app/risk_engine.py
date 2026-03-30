"""
Motor de Riesgo Cuantitativo — Fase 2
======================================
Calcula ARO, ALE, EF y compliance alerts por activo usando
los logs persistidos en normalized_features (Fase 1).

Fórmulas estándar ISO 27001/27005:
  ARO  = incident_count / years_window
  SLE  = asset_value (USD) × EF
  ALE  = SLE × ARO
  EF   = exposure_factor por tipo de evento (0.0 - 1.0)

Nota de diseño:
  - El motor NO tiene acceso a la BD del GRC.
  - Recibe asset_value desde el payload del cliente (Sentinel lo manda con el log).
  - Los valores monetarios son sugerencias para el GRC — éste hace el cálculo final.
  - El motor sólo necesita: conteo de incidentes reales + severidad promedio + tipo de patrón.
"""
import hashlib, json, logging
from datetime import datetime, timezone, timedelta
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# ── Mapeo de patrones de ataque → control ISO 27001 violado + EF base ────────
PATTERN_MAP = {
    "brute_force_attempt": {
        "control_id":       "A.9.4.2",   # Secure log-on procedures
        "control_name":     "Procedimientos de inicio de sesión seguro",
        "ef_base":          0.4,          # 40% del activo dañado si tiene éxito
        "risk_scenario":    "unauthorized_access",
    },
    "successful_login": {
        "control_id":       "A.9.4.2",
        "control_name":     "Procedimientos de inicio de sesión seguro",
        "ef_base":          0.7,          # Login exitoso post-brute = mayor impacto
        "risk_scenario":    "unauthorized_access",
    },
    "lateral_movement": {
        "control_id":       "A.13.1.3",  # Segregation in networks
        "control_name":     "Segregación en redes",
        "ef_base":          0.6,
        "risk_scenario":    "network_breach",
    },
    "suspicious_execution": {
        "control_id":       "A.12.6.2",  # Restrictions on software installation
        "control_name":     "Restricciones de instalación de software",
        "ef_base":          0.5,
        "risk_scenario":    "malware_execution",
    },
    "persistence": {
        "control_id":       "A.12.6.1",  # Management of technical vulnerabilities
        "control_name":     "Gestión de vulnerabilidades técnicas",
        "ef_base":          0.7,
        "risk_scenario":    "persistence_mechanism",
    },
    "data_exfiltration": {
        "control_id":       "A.8.3.1",   # Management of removable media
        "control_name":     "Gestión de medios removibles / DLP",
        "ef_base":          0.9,          # Exfiltración = alto impacto
        "risk_scenario":    "data_breach",
    },
    "reconnaissance": {
        "control_id":       "A.13.1.1",  # Network controls
        "control_name":     "Controles de red",
        "ef_base":          0.2,          # Solo recon = bajo impacto directo
        "risk_scenario":    "reconnaissance",
    },
    "c2_beacon": {
        "control_id":       "A.13.2.1",  # Information transfer policies
        "control_name":     "Políticas de transferencia de información",
        "ef_base":          0.8,
        "risk_scenario":    "c2_communication",
    },
    "blocked_attempt": {
        "control_id":       "A.13.1.1",
        "control_name":     "Controles de red",
        "ef_base":          0.1,          # Bloqueado = muy bajo impacto real
        "risk_scenario":    "blocked_attack",
    },
    "high_severity_event": {
        "control_id":       "A.16.1.2",  # Reporting information security events
        "control_name":     "Reporte de eventos de seguridad",
        "ef_base":          0.5,
        "risk_scenario":    "security_incident",
    },
}

DEFAULT_PATTERN = {
    "control_id":    "A.16.1.1",
    "control_name":  "Responsabilidades y procedimientos",
    "ef_base":       0.3,
    "risk_scenario": "generic_incident",
}

# ── Clase principal del motor ─────────────────────────────────────────────────

class RiskEngine:
    """
    Motor de cálculo de riesgo cuantitativo.
    Trabaja con psycopg2 síncrono (compatible con Celery y tests).
    """

    def __init__(self, db_url: str):
        self._db_url = db_url

    def _connect(self):
        return psycopg2.connect(self._db_url, cursor_factory=RealDictCursor)

    # ── API pública ───────────────────────────────────────────────────────────

    def calculate_risk_for_asset(
        self,
        client_id:   str,
        asset_id:    str,
        pattern:     str,
        window_days: int = 30,
        asset_value: float = 0.5,     # 0.0-1.0 — viene del payload del cliente
    ) -> dict:
        """
        Calcula las métricas de riesgo para un activo específico.

        Args:
            client_id:   ID del cliente (Sentinel key)
            asset_id:    ID técnico del activo (hostname, agent.name, etc.)
            pattern:     Patrón de ataque detectado (del normalizador)
            window_days: Ventana temporal para contar incidentes (default: 30 días)
            asset_value: Valor normalizado del activo (0.0-1.0)

        Returns:
            dict con ARO, ALE (delta), EF, compliance info y payload listo para el GRC
        """
        pattern_info = PATTERN_MAP.get(pattern, DEFAULT_PATTERN)

        # 1. Contar incidentes reales en la ventana temporal
        incident_count = self._count_incidents(client_id, asset_id, window_days)

        # 2. Calcular métricas cuantitativas
        aro              = self._compute_aro(incident_count, window_days)
        ef               = self._compute_ef(pattern_info["ef_base"], asset_value)
        ale_delta        = self._compute_ale_delta(asset_value, ef, aro)
        evidence_hash    = self._compute_evidence_hash(client_id, asset_id, pattern, incident_count)

        # 3. Obtener ARO histórico para calcular delta
        previous_aro     = self._get_previous_aro(client_id, asset_id, pattern_info["risk_scenario"])
        aro_delta        = round(aro - previous_aro, 4)

        # 4. Persistir resultado en risk_metrics
        self._persist_risk_metric(
            client_id       = client_id,
            asset_id        = asset_id,
            risk_scenario   = pattern_info["risk_scenario"],
            window_days     = window_days,
            incident_count  = incident_count,
            calculated_aro  = aro,
            exposure_factor = ef,
            ale_delta       = ale_delta,
            failed_control  = pattern_info["control_id"],
            evidence_hash   = evidence_hash,
        )

        # 5. Construir payload completo para el GRC
        return self._build_grc_payload(
            client_id        = client_id,
            asset_id         = asset_id,
            pattern          = pattern,
            pattern_info     = pattern_info,
            incident_count   = incident_count,
            aro              = aro,
            ef               = ef,
            ale_delta        = ale_delta,
            aro_delta        = aro_delta,
            evidence_hash    = evidence_hash,
        )

    # ── Cálculos cuantitativos ────────────────────────────────────────────────

    def _compute_aro(self, incident_count: int, window_days: int) -> float:
        """
        ARO = (incidentes en la ventana) / (ventana en años)
        Si hubo 12 incidentes en 30 días → ARO ≈ 146 (casi un ataque diario)
        Si hubo 2 incidentes en 30 días  → ARO ≈ 24.3 (2 veces al mes)
        """
        if incident_count == 0:
            return 0.0
        years_in_window = window_days / 365.25
        return round(incident_count / years_in_window, 4)

    def _compute_ef(self, ef_base: float, asset_value: float) -> float:
        """
        EF ajustado = EF_base × (1 + asset_value / 2)
        Un activo de mayor valor tiene mayor EF porque hay más que perder.
        Limitado a 0.0 - 1.0.
        """
        adjusted = ef_base * (1 + asset_value / 2)
        return round(min(adjusted, 1.0), 4)

    def _compute_ale_delta(self, asset_value: float, ef: float, aro: float) -> float:
        """
        ALE delta sugerido (en unidades relativas al valor del activo).
        El GRC aplica el valor monetario real del activo para convertirlo a USD.

        Fórmula: ALE_delta = asset_value × EF × ARO × 10,000
        (El 10,000 es el factor de conversión a una escala monetaria base)
        """
        return round(asset_value * ef * aro * 10_000, 2)

    # ── Acceso a datos ────────────────────────────────────────────────────────

    def _count_incidents(self, client_id: str, asset_id: str, window_days: int) -> int:
        """Cuenta incidentes reales persistidos en normalized_features en la ventana."""
        since = datetime.now(timezone.utc) - timedelta(days=window_days)
        conn  = None
        try:
            conn = self._connect()
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) as cnt
                    FROM normalized_features
                    WHERE client_id = %s
                      AND asset_id  = %s
                      AND timestamp_event >= %s
                      AND severity_score  >= 0.4
                """, (client_id, asset_id, since))
                row = cur.fetchone()
                return int(row["cnt"]) if row else 0
        except Exception as e:
            logger.warning(f"RiskEngine: no se pudo contar incidentes: {e}")
            return 0
        finally:
            if conn:
                conn.close()

    def _get_previous_aro(self, client_id: str, asset_id: str, risk_scenario: str) -> float:
        """Obtiene el ARO del cálculo previo para computar tendencia."""
        conn = None
        try:
            conn = self._connect()
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT calculated_aro
                    FROM risk_metrics
                    WHERE client_id    = %s
                      AND asset_id     = %s
                      AND risk_scenario = %s
                    ORDER BY calculated_at DESC
                    LIMIT 1
                """, (client_id, asset_id, risk_scenario))
                row = cur.fetchone()
                return float(row["calculated_aro"]) if row else 0.0
        except Exception as e:
            logger.warning(f"RiskEngine: no se pudo obtener ARO previo: {e}")
            return 0.0
        finally:
            if conn:
                conn.close()

    def _persist_risk_metric(
        self, client_id, asset_id, risk_scenario, window_days,
        incident_count, calculated_aro, exposure_factor,
        ale_delta, failed_control, evidence_hash
    ) -> None:
        """Persiste el cálculo de riesgo en risk_metrics para historial."""
        window_start = datetime.now(timezone.utc) - timedelta(days=window_days)
        conn = None
        try:
            conn = psycopg2.connect(self._db_url)  # sin RealDictCursor para insert
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO risk_metrics
                    (client_id, asset_id, risk_scenario, window_days, incident_count,
                     calculated_aro, exposure_factor, ale_delta, failed_control_id,
                     evidence_hash, window_start, window_end)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (client_id, asset_id, risk_scenario, window_days, incident_count,
                      calculated_aro, exposure_factor, ale_delta, failed_control,
                      evidence_hash, window_start))
            conn.commit()
            logger.info(
                f"RiskEngine: persistido — asset={asset_id} ARO={calculated_aro} "
                f"EF={exposure_factor} ALE_delta={ale_delta}"
            )
        except Exception as e:
            logger.error(f"RiskEngine: error al persistir métricas: {e}")
        finally:
            if conn:
                conn.close()

    # ── Construcción del payload GRC ──────────────────────────────────────────

    def _build_grc_payload(
        self, client_id, asset_id, pattern, pattern_info,
        incident_count, aro, ef, ale_delta, aro_delta, evidence_hash
    ) -> dict:
        """
        Construye el payload final que el GRC forwarder enviará al GRC.
        Formato exacto que acepta el endpoint /api/v1/integrations/telemetry del GRC.
        """
        now = datetime.now(timezone.utc).isoformat()
        trend = "increase" if aro_delta > 0 else ("decrease" if aro_delta < 0 else "stable")

        return {
            # ── Identificación del evento ─────────────────────────────────
            "risk_impact_update": {
                "asset_id":                 asset_id,
                "risk_scenario":            pattern_info["risk_scenario"],
                "calculated_aro":           aro,
                "suggested_exposure_factor": ef,
                "calculated_ale_delta":     ale_delta,
                "aro_trend":                trend,
                "aro_delta":                aro_delta,
                "incident_count_window":    incident_count,
                "asset_value_normalized":   None,   # el GRC tiene el valor real
            },
            # ── Control ISO 27001 violado ─────────────────────────────────
            "compliance_alert": {
                "failed_control_id":  pattern_info["control_id"],
                "control_name":       pattern_info["control_name"],
                "risk_scenario":      pattern_info["risk_scenario"],
                "evidence_hash":      evidence_hash,
                "calculated_at":      now,
            },
            # ── Estado del incidente ──────────────────────────────────────
            "status":          "INCIDENT_REPORTED",
            "pattern_detected": pattern,
            "sentinel_version": "2.0",
        }

    @staticmethod
    def _compute_evidence_hash(client_id: str, asset_id: str, pattern: str, count: int) -> str:
        """SHA-256 determinístico del contexto del incidente para auditoría."""
        data = f"{client_id}:{asset_id}:{pattern}:{count}:{datetime.now(timezone.utc).date()}"
        return "sha256:" + hashlib.sha256(data.encode()).hexdigest()[:32]

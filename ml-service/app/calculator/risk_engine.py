"""
calculator/risk_engine.py
==========================
Motor de cálculo de riesgo cuantitativo ISO 27005.

Fórmulas implementadas (estándar, no inventadas):
  EF  = Exposure Factor      → fracción del valor del activo que se pierde
  SLE = Single Loss Expectancy = valor_activo × EF
  ARO = Annualized Rate of Occurrence → derivado del historial real en normalized_features
  ALE = Annualized Loss Expectancy = SLE × ARO

CIA (Confidencialidad / Integridad / Disponibilidad):
  No entra en EF, SLE, ARO ni ALE.
  Se usa para identificar qué dimensiones de seguridad fueron impactadas
  y con qué criticidad para ese activo específico.
  Resultado en 'impacted_dimensions' — contexto de impacto, no input de fórmula.

ARO se calcula desde normalized_features (historial real del activo):
  - Agrupa eventos del mismo src_ip + asset_id + event_type en ventanas de
    SESSION_GAP_MINUTES minutos → cada grupo = 1 sesión de ataque (incidente).
  - Contar paquetes individuales como incidentes separados infla el ARO
    de forma irreal (ej: 500 paquetes/min → ARO 8,000+).
  - Con sesiones, 500 paquetes en 10 min = 1 incidente, que es la
    interpretación correcta bajo ISO 27005.
  - Si no hay historial suficiente → ARO = 1.0 con aro_confidence = 'insufficient_data'
    (baseline conservador per ISO 27005 cuando no hay datos históricos).

Separado de escalate_task para poder testearlo de forma independiente.
"""

import logging
from psycopg2.extensions import connection as PgConnection

logger = logging.getLogger(__name__)


# ── Tablas de referencia ──────────────────────────────────────────────────────

PATTERN_EF: dict[str, float] = {
    "ransomware_activity":   0.90,
    "data_exfiltration":     0.80,
    "c2_reverse_shell":      0.75,
    "credential_theft":      0.70,
    "cloud_attack":          0.70,
    "lateral_movement":      0.65,
    "privilege_escalation":  0.60,
    "c2_beacon":             0.55,
    "brute_force_success":   0.50,
    "defense_evasion":       0.45,
    "persistence":           0.40,
    "suspicious_execution":  0.35,
    "iot_anomaly":           0.35,
    "web_attack":            0.30,
    "brute_force_attempt":   0.25,
    "wireless_threat":       0.25,
    "reconnaissance":        0.20,
    "high_severity_event":   0.40,
    "none":                  0.10,
}

PATTERN_CIA_IMPACT: dict[str, list[str]] = {
    "ransomware_activity":   ["disponibilidad", "integridad"],
    "data_exfiltration":     ["confidencialidad"],
    "credential_theft":      ["confidencialidad", "integridad"],
    "lateral_movement":      ["confidencialidad", "integridad", "disponibilidad"],
    "privilege_escalation":  ["confidencialidad", "integridad"],
    "c2_reverse_shell":      ["confidencialidad", "disponibilidad"],
    "c2_beacon":             ["confidencialidad"],
    "brute_force_success":   ["confidencialidad", "integridad"],
    "brute_force_attempt":   ["disponibilidad"],
    "cloud_attack":          ["confidencialidad", "integridad", "disponibilidad"],
    "defense_evasion":       ["integridad"],
    "persistence":           ["integridad", "disponibilidad"],
    "reconnaissance":        ["confidencialidad"],
    "web_attack":            ["confidencialidad", "integridad"],
    "iot_anomaly":           ["disponibilidad", "integridad"],
    "wireless_threat":       ["confidencialidad"],
    "suspicious_execution":  ["integridad", "disponibilidad"],
    "high_severity_event":   ["confidencialidad", "integridad", "disponibilidad"],
    "none":                  [],
}

ARO_MAX_PERIOD_DAYS = 365
ARO_MIN_PERIOD_DAYS = 30

ARO_HIGH_CONFIDENCE_EVENTS   = 10
ARO_HIGH_CONFIDENCE_DAYS     = 180
ARO_MEDIUM_CONFIDENCE_EVENTS = 3
ARO_MEDIUM_CONFIDENCE_DAYS   = 60

# Ventana de sesión: eventos del mismo origen separados por menos de
# SESSION_GAP_MINUTES minutos se consideran el mismo incidente.
# Valor razonado: un escaneo de puertos o ataque de fuerza bruta típico
# dura menos de 5 minutos. Dos ráfagas separadas por más de 5 min
# se consideran incidentes distintos.
SESSION_GAP_MINUTES = 5


# ── Punto de entrada principal ────────────────────────────────────────────────

def calculate_risk(
    conn: PgConnection,
    client_id: str,
    asset_id: str,
    pattern: str,
    asset_meta: dict,
    anomaly_score: float,
) -> dict:
    valor_activo = float(asset_meta.get("valor_activo") or 0.0)
    pattern_key  = pattern if pattern in PATTERN_EF else "none"

    ef  = PATTERN_EF[pattern_key]
    sle = round(valor_activo * ef, 2)

    aro_result = _calculate_aro(conn, client_id, asset_id, pattern)
    ale        = round(sle * aro_result["aro"], 2)

    cia_snapshot = {
        "confidencialidad": asset_meta.get("valor_confidencialidad", 3),
        "integridad":       asset_meta.get("valor_integridad",       3),
        "disponibilidad":   asset_meta.get("valor_disponibilidad",   3),
    }

    affected_dims      = PATTERN_CIA_IMPACT.get(pattern_key, [])
    impacted_dimensions = {
        dim: cia_snapshot[dim]
        for dim in affected_dims
        if dim in cia_snapshot
    }

    history_ctx = _calculate_history_context(conn, client_id, asset_id, pattern)

    logger.info(
        f"risk_engine: {asset_id} pattern={pattern} "
        f"EF={ef} SLE={sle} ARO={aro_result['aro']} ALE={ale} "
        f"aro_confidence={aro_result['confidence']} "
        f"sessions={aro_result['sample_size']} "
        f"attack_count={history_ctx['attack_count']}"
    )

    return {
        "ef":                     ef,
        "sle":                    sle,
        "aro":                    aro_result["aro"],
        "ale":                    ale,
        "aro_sample_size":        aro_result["sample_size"],
        "aro_period_days":        aro_result["period_days"],
        "aro_confidence":         aro_result["confidence"],
        "valor_activo_snapshot":  valor_activo,
        "clasificacion_criticidad": asset_meta.get("clasificacion_criticidad"),
        "cia_snapshot":           cia_snapshot,
        "impacted_dimensions":    impacted_dimensions,
        "data_flags": {
            "pii": bool(asset_meta.get("contiene_pii", False)),
            "pci": bool(asset_meta.get("contiene_pci", False)),
            "phi": bool(asset_meta.get("contiene_phi", False)),
            "pfi": bool(asset_meta.get("contiene_pfi", False)),
        },
        "attack_count_historical":  history_ctx["attack_count"],
        "first_occurrence_pattern": history_ctx["first_occurrence"],
        "recurrence_flag":          history_ctx["recurrence"],
    }


# ── ARO basado en sesiones de ataque ─────────────────────────────────────────

def _calculate_aro(
    conn: PgConnection,
    client_id: str,
    asset_id: str,
    pattern: str,
) -> dict:
    """
    Calcula ARO contando SESIONES DE ATAQUE, no eventos individuales.

    Una sesión = grupo de eventos del mismo src_ip + asset_id + event_type
    separados por menos de SESSION_GAP_MINUTES minutos entre sí.

    Fórmula:
        sesiones     = número de grupos de eventos agrupados por ventana temporal
        período_días = días entre primer y último evento (capped 30-365)
        ARO          = sesiones / (período_días / 365)

    Ejemplo real:
        500 paquetes bloqueados en 10 min desde el mismo IP
        → 1 sesión (no 500 incidentes)
        → ARO = 1 sesión / (30/365) ≈ 12 al año (razonable)
        vs ARO anterior = 500 / (30/365) ≈ 6,000 (irreal)

    Si no hay datos suficientes → ARO = 1.0, confidence = 'insufficient_data'
    """
    cur = conn.cursor()
    try:
        event_hint = _pattern_to_event_hint(pattern)

        # Paso 1: obtener eventos relevantes con su timestamp y src_ip
        # Filtramos por event_type o pattern similar al actual
        cur.execute("""
            SELECT
                src_ip,
                created_at
            FROM normalized_features
            WHERE client_id  = %s
              AND asset_id   = %s
              AND created_at >= NOW() - INTERVAL '365 days'
              AND (
                  event_type ILIKE %s
                  OR features_vector->>'pattern' = %s
              )
            ORDER BY src_ip, created_at
        """, (client_id, asset_id, f"%{event_hint}%", pattern))

        rows = cur.fetchall()

        if not rows:
            return _aro_insufficient()

        # Paso 2: agrupar en sesiones por src_ip usando ventana temporal
        # Algoritmo: si el gap entre dos eventos consecutivos del mismo IP
        # supera SESSION_GAP_MINUTES → es una nueva sesión.
        from datetime import timedelta

        sessions     = 0
        prev_ip      = None
        prev_ts      = None
        gap          = timedelta(minutes=SESSION_GAP_MINUTES)
        first_ts     = rows[0][1]
        last_ts      = rows[-1][1]

        for src_ip, ts in rows:
            if src_ip != prev_ip:
                # Nuevo IP → nueva sesión siempre
                sessions += 1
            elif (ts - prev_ts) > gap:
                # Mismo IP pero gap mayor al umbral → nueva sesión
                sessions += 1
            # else: mismo IP dentro del gap → mismo incidente, no contar
            prev_ip = src_ip
            prev_ts = ts

        if sessions == 0:
            return _aro_insufficient()

        # Paso 3: calcular período en días
        period_days = max(
            int((last_ts - first_ts).days),
            ARO_MIN_PERIOD_DAYS
        )
        period_days = min(period_days, ARO_MAX_PERIOD_DAYS)

        # ARO = sesiones / fracción_del_año
        aro        = round(sessions / (period_days / 365), 4)
        confidence = _aro_confidence(sessions, period_days)

        logger.info(
            f"risk_engine ARO: {asset_id} — "
            f"eventos_raw={len(rows)} sesiones={sessions} "
            f"período={period_days}d ARO={aro} conf={confidence}"
        )

        return {
            "aro":         aro,
            "sample_size": sessions,   # ahora representa sesiones, no eventos raw
            "period_days": period_days,
            "confidence":  confidence,
        }

    except Exception as e:
        logger.error(f"risk_engine: error calculando ARO para {asset_id} — {e}")
        return _aro_insufficient()
    finally:
        cur.close()


def _aro_insufficient() -> dict:
    return {
        "aro":         1.0,
        "sample_size": 0,
        "period_days": 0,
        "confidence":  "insufficient_data",
    }


def _aro_confidence(events: int, period_days: int) -> str:
    if events >= ARO_HIGH_CONFIDENCE_EVENTS and period_days >= ARO_HIGH_CONFIDENCE_DAYS:
        return "high"
    if events >= ARO_MEDIUM_CONFIDENCE_EVENTS and period_days >= ARO_MEDIUM_CONFIDENCE_DAYS:
        return "medium"
    return "low"


def _pattern_to_event_hint(pattern: str) -> str:
    hints = {
        "ransomware_activity":   "ransom",
        "data_exfiltration":     "download",
        "credential_theft":      "credential",
        "lateral_movement":      "auth",
        "privilege_escalation":  "admin",
        "c2_reverse_shell":      "shell",
        "c2_beacon":             "beacon",
        "brute_force_success":   "login",
        "brute_force_attempt":   "failed",
        "cloud_attack":          "cloud",
        "defense_evasion":       "defender",
        "persistence":           "scheduled",
        "reconnaissance":        "scan",
        "web_attack":            "http",
        "iot_anomaly":           "sensor",
        "wireless_threat":       "wifi",
        "suspicious_execution":  "exec",
    }
    return hints.get(pattern, pattern.replace("_", " "))


# ── Contexto histórico ────────────────────────────────────────────────────────

def _calculate_history_context(
    conn: PgConnection,
    client_id: str,
    asset_id: str,
    pattern: str,
) -> dict:
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*)
            FROM ml_recommendations
            WHERE client_id = %s AND asset_id = %s
        """, (client_id, asset_id))
        attack_count = int(cur.fetchone()[0] or 0)

        cur.execute("""
            SELECT COUNT(*)
            FROM ml_recommendations
            WHERE client_id = %s AND asset_id = %s AND pattern = %s
        """, (client_id, asset_id, pattern))
        pattern_count = int(cur.fetchone()[0] or 0)

        return {
            "attack_count":     attack_count,
            "first_occurrence": pattern_count == 0,
            "recurrence":       pattern_count > 0,
        }

    except Exception as e:
        logger.error(f"risk_engine: error en history_context para {asset_id} — {e}")
        return {"attack_count": 0, "first_occurrence": True, "recurrence": False}
    finally:
        cur.close()
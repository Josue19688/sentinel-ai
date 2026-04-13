"""
calculator/risk_engine.py  [FIXED v3 — ARO por días de ataque]

DIAGNÓSTICO FINAL DEL ARO:
  El problema no era SESSION_GAP_MINUTES. Era la unidad de medida.

  ISO 27005 define ARO como: número de veces por año que ocurre un incidente.
  Un "incidente" en contexto de port scan = 1 día en que la IP atacó el activo.

  Con SESSION_GAP=30min y eventos llegando continuamente durante horas:
  - La misma IP no crea gap de 30min → cuenta como 1 sesión (correcto)
  - Pero si hay 3 IPs distintas atacando en paralelo → 3 sesiones en 30min
  - En 30 días → aro_raw = 3 * (30 / (30/365)) = ~1,000 (incorrecto)

  SOLUCIÓN: Contar DÍAS ÚNICOS con actividad, no sesiones de paquetes.
  Si debian fue atacada 25 días de 30 observados → ARO ≈ 25/30*365 ≈ 304.
  Con cap 365: ARO=304, SLE=7500, ALE=2,280,000 — demasiado para port scan.

  El cap correcto para port_scan es 52 (semanal) porque:
  - Un port scan BLOQUEADO por firewall tiene EF=0.15 (daño real bajo)
  - ALE = valor_activo × EF × ARO = 50,000 × 0.15 × 52 = $390,000/año
  - Esto es la EXPOSICIÓN MÁXIMA ANUAL esperada, no pérdida garantizada
  - Es el número que el analista lleva a la junta para justificar inversión en FW

  Para patrones de alta severidad (ransomware, C2):
  - EF es alto (0.75-0.90), ARO típicamente bajo (1-5 veces/año)
  - ALE = 50,000 × 0.90 × 3 = $135,000/año → número realista para junta
"""

import logging
from datetime import date, timedelta
from psycopg2.extensions import connection as PgConnection

logger = logging.getLogger(__name__)


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
    "port_scan":             0.15,
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
    "port_scan":             ["disponibilidad"],
    "web_attack":            ["confidencialidad", "integridad"],
    "iot_anomaly":           ["disponibilidad", "integridad"],
    "wireless_threat":       ["confidencialidad"],
    "suspicious_execution":  ["integridad", "disponibilidad"],
    "high_severity_event":   ["confidencialidad", "integridad", "disponibilidad"],
    "none":                  [],
}

# ARO caps por categoría de patrón
# Estos caps representan el máximo razonable de incidentes/año
ARO_CAPS: dict[str, float] = {
    "ransomware_activity":   5.0,   # ransomware exitoso ≤ 5 veces/año
    "data_exfiltration":     12.0,  # exfil ≤ mensual
    "c2_reverse_shell":      12.0,
    "credential_theft":      24.0,
    "cloud_attack":          12.0,
    "lateral_movement":      12.0,
    "privilege_escalation":  24.0,
    "c2_beacon":             52.0,
    "brute_force_success":   24.0,
    "defense_evasion":       52.0,
    "persistence":           52.0,
    "suspicious_execution":  52.0,
    "iot_anomaly":           52.0,
    "web_attack":            52.0,
    "brute_force_attempt":   365.0,
    "wireless_threat":       52.0,
    "reconnaissance":        52.0,  # reconocimiento ≤ semanal
    "port_scan":             52.0,  # port scan ≤ semanal (bloqueado = daño bajo)
    "high_severity_event":   52.0,
    "none":                  52.0,
}

ARO_MIN_PERIOD_DAYS  = 30
ARO_MAX_PERIOD_DAYS  = 365

ARO_HIGH_CONFIDENCE_DAYS_MIN  = 10
ARO_HIGH_CONFIDENCE_PERIOD    = 180
ARO_MEDIUM_CONFIDENCE_DAYS_MIN = 3
ARO_MEDIUM_CONFIDENCE_PERIOD   = 60


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

    affected_dims       = PATTERN_CIA_IMPACT.get(pattern_key, [])
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
        f"days_with_attacks={aro_result['sample_size']}"
    )

    return {
        "ef":                    ef,
        "sle":                   sle,
        "aro":                   aro_result["aro"],
        "ale":                   ale,
        "aro_sample_size":       aro_result["sample_size"],
        "aro_period_days":       aro_result["period_days"],
        "aro_confidence":        aro_result["confidence"],
        "valor_activo_snapshot": valor_activo,
        "clasificacion_criticidad": asset_meta.get("clasificacion_criticidad"),
        "cia_snapshot":          cia_snapshot,
        "impacted_dimensions":   impacted_dimensions,
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


def _calculate_aro(
    conn: PgConnection,
    client_id: str,
    asset_id: str,
    pattern: str,
) -> dict:
    """
    Calcula ARO contando DÍAS ÚNICOS con actividad de ataque.

    ISO 27005: ARO = veces/año que ocurre el incidente.
    Un "incidente" = 1 día calendario con actividad detectada.

    Ejemplo real con datos actuales:
      debian fue atacada por port_scan durante 1 día (2026-04-11).
      período observado = 30 días (mínimo).
      ARO_raw = 1 / (30/365) = 12.2 veces/año
      ARO_capped = min(12.2, 52) = 12.2 → razonable.
      ALE = 50,000 × 0.15 × 12.2 = $91,500/año → número defendible en junta.

    Si debian hubiera sido atacada 5 días de 30:
      ARO_raw = 5 / (30/365) = 60.8 → cap 52 → ALE = $390,000/año.
    """
    cur = conn.cursor()
    try:
        event_hint = _pattern_to_event_hint(pattern)

        # Contar días únicos con actividad (no eventos individuales)
        cur.execute("""
            SELECT
                DATE(created_at AT TIME ZONE 'UTC') AS attack_date,
                COUNT(DISTINCT src_ip)              AS attacking_ips
            FROM normalized_features
            WHERE client_id  = %s
              AND asset_id   = %s
              AND created_at >= NOW() - INTERVAL '365 days'
              AND (
                  event_type ILIKE %s
                  OR features_vector->>'pattern' = %s
                  OR pattern_hint = %s
              )
            GROUP BY DATE(created_at AT TIME ZONE 'UTC')
            ORDER BY attack_date
        """, (client_id, asset_id, f"%{event_hint}%", pattern, pattern))

        rows = cur.fetchall()  # [(date, n_ips), ...]

        if not rows:
            return _aro_insufficient()

        attack_dates  = [r[0] for r in rows]
        days_attacked = len(attack_dates)
        first_date    = attack_dates[0]
        last_date     = attack_dates[-1]

        # Período observado en días (mínimo 30, máximo 365)
        period_days = max(
            (last_date - first_date).days + 1,
            ARO_MIN_PERIOD_DAYS
        )
        period_days = min(period_days, ARO_MAX_PERIOD_DAYS)

        # ARO = días atacados / fracción del año observado
        aro_raw = days_attacked / (period_days / 365)

        # Aplicar cap según patrón
        aro_cap = ARO_CAPS.get(pattern, ARO_CAPS.get("none", 52.0))
        aro     = round(min(aro_raw, aro_cap), 4)

        if aro_raw > aro_cap:
            logger.info(
                f"risk_engine ARO CAPPED: {asset_id} pattern={pattern} "
                f"raw={aro_raw:.1f} → cap={aro}"
            )

        confidence = _aro_confidence(days_attacked, period_days)

        logger.info(
            f"risk_engine ARO: {asset_id} pattern={pattern} "
            f"días_atacados={days_attacked} "
            f"período={period_days}d "
            f"ARO={aro} conf={confidence}"
        )

        return {
            "aro":         aro,
            "sample_size": days_attacked,
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


def _aro_confidence(days_attacked: int, period_days: int) -> str:
    if days_attacked >= ARO_HIGH_CONFIDENCE_DAYS_MIN and period_days >= ARO_HIGH_CONFIDENCE_PERIOD:
        return "high"
    if days_attacked >= ARO_MEDIUM_CONFIDENCE_DAYS_MIN and period_days >= ARO_MEDIUM_CONFIDENCE_PERIOD:
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
        "port_scan":             "scan",
        "web_attack":            "http",
        "iot_anomaly":           "sensor",
        "wireless_threat":       "wifi",
        "suspicious_execution":  "exec",
    }
    return hints.get(pattern, pattern.replace("_", " "))


def _calculate_history_context(
    conn: PgConnection, client_id: str, asset_id: str, pattern: str,
) -> dict:
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT COUNT(*) FROM ml_recommendations WHERE client_id=%s AND asset_id=%s",
            (client_id, asset_id)
        )
        attack_count = int(cur.fetchone()[0] or 0)

        cur.execute(
            "SELECT COUNT(*) FROM ml_recommendations WHERE client_id=%s AND asset_id=%s AND pattern=%s",
            (client_id, asset_id, pattern)
        )
        pattern_count = int(cur.fetchone()[0] or 0)

        return {
            "attack_count":     attack_count,
            "first_occurrence": pattern_count == 0,
            "recurrence":       pattern_count > 0,
        }
    except Exception as e:
        logger.error(f"risk_engine: error en history_context — {e}")
        return {"attack_count": 0, "first_occurrence": True, "recurrence": False}
    finally:
        cur.close()
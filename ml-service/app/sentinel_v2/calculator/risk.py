"""
calculator/risk.py
==================
Responsabilidad ÚNICA: calcular métricas de riesgo ISO 27005
a partir de un evento normalizado.

Funciona de forma INDEPENDIENTE: recibe un dict con los campos
canónicos y devuelve las métricas de riesgo. No sabe nada de
parsers ni de fuentes de logs.

Fórmulas ISO 27005:
  AV  = Asset Value (valor monetario del activo en USD)
  EF  = Exposure Factor (% del activo que se pierde si ocurre el incidente)
  SLE = Single Loss Expectancy = AV × EF
  ARO = Annual Rate of Occurrence (ocurrencias por año estimadas)
  ALE = Annual Loss Expectancy = SLE × ARO

Nota sobre numeric_value (IoT):
  Si el evento tiene un valor numérico de sensor (temperatura, presión...),
  calculamos una anomaly_ratio comparando contra umbrales conocidos.
  Eso aumenta el EF en eventos industriales.
"""

from dataclasses import dataclass
from typing import Optional
import math


# ── Valor de activo por tipo de nombre ───────────────────────────────────────
_ASSET_VALUE_MAP = {
    "db":       0.95,   # base de datos de producción
    "prod":     0.90,
    "finance":  0.95,
    "backup":   0.85,
    "web":      0.60,
    "api":      0.65,
    "srv":      0.70,
    "server":   0.70,
    "cloud":    0.80,
    "iot":      0.50,
    "sensor":   0.40,
    "ws":       0.35,   # workstation
    "ventas":   0.40,
}

_DEFAULT_ASSET_VALUE_USD = 50_000.0   # valor base cuando no sabemos el activo


@dataclass
class RiskMetrics:
    asset_value_score: float    # 0.0 – 1.0
    asset_value_usd:   float
    exposure_factor:   float    # 0.0 – 1.0
    sle_usd:           float
    aro:               float    # ocurrencias/año
    ale_usd:           float
    risk_level:        str      # low | medium | high | critical
    action:            str      # ignore | review | escalate | contain
    iso_control:       str      # control ISO 27001 afectado (A.9.2.1, etc.)
    anomaly_ratio:     float    # para IoT: qué tan lejos del baseline (0.0–∞)


def calculate(event: dict) -> RiskMetrics:
    """
    Calcula métricas de riesgo ISO 27005 para un evento normalizado.
    event debe tener al menos: asset_id, severity_score, pattern_hint.
    """
    asset_id      = str(event.get("asset_id", "unknown")).lower()
    severity      = float(event.get("severity_score", 0.2))
    pattern       = str(event.get("pattern_hint", "none"))
    numeric_value = event.get("numeric_value")     # IoT: temperatura, presión...
    parse_conf    = float(event.get("parse_confidence", 1.0))

    # 1. Valor del activo
    av_score = _get_asset_value(asset_id)
    av_usd   = av_score * _DEFAULT_ASSET_VALUE_USD

    # 2. Exposure Factor
    ef = _get_exposure_factor(pattern, severity, av_score)

    # 3. Anomalía IoT: si hay un valor numérico, calcular desviación
    anomaly_ratio = 0.0
    if numeric_value is not None:
        anomaly_ratio = _iot_anomaly_ratio(numeric_value, asset_id, event)
        if anomaly_ratio > 2.0:
            # Valor numérico fuera de rango → elevar EF
            ef = min(0.99, ef + (anomaly_ratio - 2.0) * 0.1)
            severity = min(1.0, severity + 0.3)

    # 4. Reducir score si parse_confidence es baja (datos incompletos = incertidumbre)
    if parse_conf < 0.4:
        severity = max(severity, 0.3)  # no ignorar, pero no elevar sin evidencia

    # 5. SLE, ARO, ALE
    sle = av_usd * ef
    aro = _estimate_aro(pattern, severity)
    ale = sle * aro

    # 6. Nivel de riesgo y acción
    risk_level, action = _risk_decision(severity, pattern, ale)

    return RiskMetrics(
        asset_value_score = round(av_score, 3),
        asset_value_usd   = round(av_usd, 2),
        exposure_factor   = round(ef, 3),
        sle_usd           = round(sle, 2),
        aro               = round(aro, 2),
        ale_usd           = round(ale, 2),
        risk_level        = risk_level,
        action            = action,
        iso_control       = _get_iso_control(pattern),
        anomaly_ratio     = round(anomaly_ratio, 3),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_asset_value(asset_id: str) -> float:
    """Estima el valor del activo basado en keywords en su nombre."""
    for keyword, value in _ASSET_VALUE_MAP.items():
        if keyword in asset_id:
            return value
    return 0.5  # valor medio por defecto


def _get_exposure_factor(pattern: str, severity: float, av: float) -> float:
    """
    EF según el tipo de amenaza y el valor del activo.
    Más valor del activo = más impacto potencial.
    """
    pattern_ef = {
        "ransomware_activity":   0.90,
        "c2_reverse_shell":      0.85,
        "credential_theft":      0.80,
        "privilege_escalation":  0.75,
        "defense_evasion":       0.70,
        "cloud_attack":          0.85,
        "data_exfiltration":     0.75,
        "suspicious_execution":  0.65,
        "web_attack":            0.60,
        "brute_force_attempt":   0.40,
        "reconnaissance":        0.25,
        "iot_anomaly":           0.60,
        "wireless_threat":       0.50,
        "persistence":           0.70,
        "high_severity_event":   0.55,
        "none":                  0.10,
    }
    base_ef = pattern_ef.get(pattern, 0.20)
    # Modular por severidad y valor del activo
    return round(min(0.99, base_ef * (0.5 + severity * 0.5) * (0.7 + av * 0.3)), 3)


def _estimate_aro(pattern: str, severity: float) -> float:
    """
    Estima cuántas veces al año podría ocurrir este tipo de evento.
    Basado en patrones MITRE ATT&CK frecuencia de ocurrencia.
    """
    base_aro = {
        "brute_force_attempt":  52.0,   # semanal en promedio
        "reconnaissance":       24.0,
        "web_attack":           12.0,
        "suspicious_execution": 6.0,
        "defense_evasion":      4.0,
        "privilege_escalation": 3.0,
        "credential_theft":     3.0,
        "data_exfiltration":    2.0,
        "persistence":          2.0,
        "c2_reverse_shell":     1.0,
        "ransomware_activity":  0.5,
        "cloud_attack":         2.0,
        "iot_anomaly":          8.0,
        "wireless_threat":      4.0,
        "high_severity_event":  1.0,
        "none":                 0.1,
    }
    base = base_aro.get(pattern, 1.0)
    # Escalar por severidad
    return round(base * (0.5 + severity), 2)


def _iot_anomaly_ratio(value: float, asset_id: str, event: dict) -> float:
    """
    Para eventos IoT con valor numérico: calcula qué tan anómalo es el valor.
    Compara contra umbrales conocidos por tipo de sensor (topic).
    ratio > 1.0 = dentro de rango de alerta
    ratio > 2.0 = crítico
    """
    topic = str(event.get("event_name", "")).lower()

    # Umbrales por tipo de lectura (normal_max, critical_max)
    thresholds = {
        "temp":     (60.0,  100.0),   # Celsius
        "pressure": (20.0,   35.0),   # PSI
        "humidity": (80.0,   95.0),   # %
        "voltage":  (250.0, 300.0),   # V
        "current":  (15.0,   25.0),   # A
    }

    for sensor_type, (normal_max, critical_max) in thresholds.items():
        if sensor_type in topic or sensor_type in asset_id:
            if value <= normal_max:
                return 0.0
            return round((value - normal_max) / (critical_max - normal_max + 1), 3)

    # Sin umbral conocido: comparar contra 100 como referencia genérica
    if value > 100:
        return round(math.log10(value / 100 + 1), 3)
    return 0.0


def _risk_decision(severity: float, pattern: str, ale: float) -> tuple[str, str]:
    """Devuelve (nivel_riesgo, acción) basado en severidad, patrón y ALE."""
    critical_patterns = {
        "ransomware_activity", "c2_reverse_shell", "credential_theft",
        "cloud_attack", "privilege_escalation",
    }
    high_patterns = {
        "defense_evasion", "suspicious_execution", "data_exfiltration",
        "persistence", "web_attack", "iot_anomaly",
    }

    if pattern in critical_patterns or severity >= 0.85 or ale >= 50_000:
        return "critical", "contain"
    if pattern in high_patterns or severity >= 0.65 or ale >= 15_000:
        return "high", "escalate"
    if severity >= 0.40 or ale >= 3_000:
        return "medium", "review"
    return "low", "ignore"


def _get_iso_control(pattern: str) -> str:
    """Mapea patrones de ataque a controles específicos de la ISO 27001."""
    mapping = {
        "ransomware_activity":   "A.17.1.1 (Continuidad)",
        "c2_reverse_shell":      "A.12.1.2 (Malware)",
        "credential_theft":      "A.9.2.1 (Acceso)",
        "privilege_escalation":  "A.9.4.1 (Privilegios)",
        "defense_evasion":       "A.12.4.1 (Logs)",
        "data_exfiltration":     "A.8.2.3 (Transferencia)",
        "brute_force_attempt":   "A.9.4.2 (Passwords)",
        "web_attack":            "A.14.2.5 (Ingeniería)",
        "iot_anomaly":           "A.13.1.1 (Redes)",
    }
    return mapping.get(pattern, "A.12.1.1 (Ops)")

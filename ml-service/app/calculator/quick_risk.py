"""
calculator/risk.py
==================
Responsabilidad UNICA: calcular metricas de riesgo ISO 27005
a partir de un evento normalizado + datos reales del activo.

Formulas ISO 27005:
  AV  = Asset Value (valor monetario del activo en USD)
  EF  = Exposure Factor (% del activo que se pierde si ocurre el incidente)
  SLE = Single Loss Expectancy = AV x EF
  ARO = Annual Rate of Occurrence (ocurrencias por anio estimadas)
  ALE = Annual Loss Expectancy = SLE x ARO

Impacto CIA:
  Cada patron de ataque tiene un impacto conocido sobre C, I, A (0-3).
  Se cruza con el valor CIA configurado en el activo (1-5) para obtener
  un score ponderado que refleja cuanto le afecta el ataque a ESE activo.
"""

from dataclasses import dataclass, field
import math


# ── Valor de activo por tipo de nombre (fallback cuando no hay activo registrado) ──
_ASSET_VALUE_MAP = {
    "db":       0.95,   "prod":    0.90,   "finance":  0.95,
    "backup":   0.85,   "web":     0.60,   "api":      0.65,
    "srv":      0.70,   "server":  0.70,   "cloud":    0.80,
    "iot":      0.50,   "sensor":  0.40,   "ws":       0.35,
    "ventas":   0.40,
}

_DEFAULT_ASSET_VALUE_USD = 50_000.0   # fallback cuando no hay activo registrado

# ── Impacto de cada tipo de ataque sobre C, I, A (0=ninguno 1=bajo 2=medio 3=alto) ──
_CIA_ATTACK_IMPACT: dict[str, dict[str, int]] = {
    "ransomware_activity":  {"C": 1, "I": 3, "A": 3},  # cifra archivos, bloquea sistemas
    "data_exfiltration":    {"C": 3, "I": 2, "A": 1},  # roba datos, puede modificarlos
    "c2_reverse_shell":     {"C": 3, "I": 3, "A": 2},  # control total
    "credential_theft":     {"C": 3, "I": 1, "A": 1},  # roba credenciales
    "privilege_escalation": {"C": 2, "I": 3, "A": 2},  # puede modificar cualquier cosa
    "defense_evasion":      {"C": 1, "I": 2, "A": 1},  # oculta actividad
    "cloud_attack":         {"C": 3, "I": 2, "A": 3},  # infra en nube comprometida
    "suspicious_execution": {"C": 1, "I": 2, "A": 2},  # proceso desconocido
    "web_attack":           {"C": 2, "I": 2, "A": 2},  # vulnerabilidad web
    "brute_force_attempt":  {"C": 2, "I": 1, "A": 1},  # intento de acceso
    "brute_force_success":  {"C": 3, "I": 2, "A": 1},  # acceso logrado
    "reconnaissance":       {"C": 2, "I": 0, "A": 0},  # solo escaneo
    "port_scan":            {"C": 1, "I": 0, "A": 0},  # mapeo de puertos
    "iot_anomaly":          {"C": 1, "I": 2, "A": 3},  # disrupcion industrial
    "wireless_threat":      {"C": 2, "I": 1, "A": 2},  # acceso inalambrico
    "persistence":          {"C": 2, "I": 3, "A": 1},  # backdoor instalado
    "high_severity_event":  {"C": 2, "I": 2, "A": 2},  # evento critico generico
    "lateral_movement":     {"C": 2, "I": 2, "A": 2},  # movimiento en red interna
    "c2_beacon":            {"C": 3, "I": 2, "A": 1},  # comunicacion con C2
    "none":                 {"C": 0, "I": 0, "A": 0},
}

_CIA_NIVEL = ["Ninguno", "Bajo", "Medio", "Alto"]  # index 0-3


@dataclass
class CIADimension:
    valor_activo:    int    # valor configurado en el activo (1-5)
    impacto_ataque:  int    # impacto del ataque sobre esta dimension (0-3)
    score:           float  # 0.0-1.0 considerando ambos
    nivel:           str    # Ninguno | Bajo | Medio | Alto | Critico
    descripcion:     str    # explicacion legible


@dataclass
class RiskMetrics:
    asset_value_score: float
    asset_value_usd:   float
    exposure_factor:   float
    sle_usd:           float
    aro:               float
    ale_usd:           float
    risk_level:        str
    action:            str
    iso_control:       str
    anomaly_ratio:     float
    # Nuevos campos
    asset_info:        dict        = field(default_factory=dict)   # datos del activo real
    cia_impact:        dict        = field(default_factory=dict)   # impacto por dimension


def calculate(event: dict, asset_data: dict | None = None) -> RiskMetrics:
    """
    Calcula metricas de riesgo ISO 27005 para un evento normalizado.

    Parametros:
      event      - evento normalizado con asset_id, severity_score, pattern_hint
      asset_data - dict con datos del activo real (de repositories/asset.py).
                   Si es None, usa valores estimados por keywords del asset_id.
    """
    asset_id      = str(event.get("asset_id", "unknown")).lower()
    severity      = float(event.get("severity_score", 0.2))
    pattern       = str(event.get("pattern_hint",  event.get("pattern", "none")))
    numeric_value = event.get("numeric_value")
    parse_conf    = float(event.get("parse_confidence", 1.0))

    # 1. Valor del activo — real si hay activo registrado, estimado si no
    if asset_data and asset_data.get("valor_activo"):
        av_usd   = float(asset_data["valor_activo"])
        # Normalizar a score 0-1 usando $1M como referencia
        av_score = min(1.0, av_usd / 1_000_000)
    else:
        av_score = _get_asset_value(asset_id)
        av_usd   = av_score * _DEFAULT_ASSET_VALUE_USD

    # 2. Exposure Factor — ajustado por flags de sensibilidad del activo
    ef = _get_exposure_factor(pattern, severity, av_score)
    if asset_data:
        # Datos sensibles elevan el EF (mas que perder si hay exfiltracion)
        if asset_data.get("contiene_pii"): ef = min(0.99, ef + 0.05)
        if asset_data.get("contiene_pci"): ef = min(0.99, ef + 0.08)
        if asset_data.get("contiene_phi"): ef = min(0.99, ef + 0.06)
        if asset_data.get("contiene_pfi"): ef = min(0.99, ef + 0.07)

    # 3. Anomalia IoT
    anomaly_ratio = 0.0
    if numeric_value is not None:
        anomaly_ratio = _iot_anomaly_ratio(numeric_value, asset_id, event)
        if anomaly_ratio > 2.0:
            ef       = min(0.99, ef + (anomaly_ratio - 2.0) * 0.1)
            severity = min(1.0, severity + 0.3)

    # 4. Reducir score si parse_confidence es baja
    if parse_conf < 0.4:
        severity = max(severity, 0.3)

    # 5. SLE, ARO, ALE
    sle = av_usd * ef
    aro = _estimate_aro(pattern, severity)
    ale = sle * aro

    # 6. Nivel de riesgo y accion
    risk_level, action = _risk_decision(severity, pattern, ale)

    # 7. Impacto CIA — cruzando el perfil del ataque con los valores del activo
    cia_impact = _compute_cia_impact(pattern, asset_data)

    # 8. Informacion del activo para incluir en la respuesta
    asset_info: dict = {}
    if asset_data:
        asset_info = {
            "id":                    asset_data.get("id"),
            "nombre":                asset_data.get("nombre_activo"),
            "tipo":                  asset_data.get("tipo_activo"),
            "hostname":              asset_data.get("hostname"),
            "ip_address":            asset_data.get("ip_address"),
            "clasificacion":         asset_data.get("clasificacion_criticidad"),
            "departamento":          asset_data.get("departamento"),
            "propietario":           asset_data.get("propietario"),
            "valor_usd":             float(asset_data.get("valor_activo", 0)),
            "contiene_pii":          asset_data.get("contiene_pii", False),
            "contiene_pci":          asset_data.get("contiene_pci", False),
            "contiene_phi":          asset_data.get("contiene_phi", False),
            "contiene_pfi":          asset_data.get("contiene_pfi", False),
        }
    else:
        asset_info = {
            "id":      None,
            "nombre":  asset_id,
            "nota":    "Activo no registrado en Sentinel ML. Carga tu inventario en /assets/upload",
        }

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
        asset_info        = asset_info,
        cia_impact        = cia_impact,
    )



# ── Helpers ───────────────────────────────────────────────────────────────────

def _compute_cia_impact(pattern: str, asset_data: dict | None) -> dict:
    """
    Calcula como el ataque afecta cada dimension CIA del activo.
    Combina el perfil del ataque (_CIA_ATTACK_IMPACT) con los valores
    configurados en el activo (valor_confidencialidad, etc.).

    Score = (impacto_ataque / 3) * (valor_activo / 5)
    Si no hay activo registrado usa CIA = 3 por defecto.
    """
    _DESCRIPCIONES = {
        "C": {
            0: "Sin impacto sobre la confidencialidad.",
            1: "Exposicion limitada de datos — monitoreaar accesos.",
            2: "Riesgo moderado de filtracion — revisar permisos urgente.",
            3: "Confidencialidad comprometida — posible fuga de datos sensibles.",
        },
        "I": {
            0: "Integridad no afectada.",
            1: "Riesgo bajo de modificacion no autorizada.",
            2: "Integridad en riesgo — verificar logs de cambios.",
            3: "Integridad comprometida — datos pueden haber sido alterados.",
        },
        "A": {
            0: "Disponibilidad no afectada.",
            1: "Impacto menor en disponibilidad.",
            2: "Servicio puede verse interrumpido — preparar contingencia.",
            3: "Alta probabilidad de interrupcion del servicio — activar BCP.",
        },
    }

    attack_cia = _CIA_ATTACK_IMPACT.get(pattern, {"C": 1, "I": 1, "A": 1})

    # Valores CIA del activo (fallback: 3 si no hay activo)
    c_val = int(asset_data.get("valor_confidencialidad", 3)) if asset_data else 3
    i_val = int(asset_data.get("valor_integridad",       3)) if asset_data else 3
    a_val = int(asset_data.get("valor_disponibilidad",   3)) if asset_data else 3

    def _dim(cia_key: str, asset_val: int) -> dict:
        ataque = attack_cia[cia_key]
        score  = round((ataque / 3) * (asset_val / 5), 3)
        nivel  = _CIA_NIVEL[ataque] if ataque < len(_CIA_NIVEL) else "Critico"
        return {
            "valor_activo_configurado": asset_val,
            "impacto_ataque":           ataque,
            "nivel":                    nivel,
            "score":                    score,
            "descripcion":              _DESCRIPCIONES[cia_key][ataque],
        }

    return {
        "confidencialidad": _dim("C", c_val),
        "integridad":       _dim("I", i_val),
        "disponibilidad":   _dim("A", a_val),
        "fuente_activo":    "registrado" if asset_data else "estimado_default",
    }

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

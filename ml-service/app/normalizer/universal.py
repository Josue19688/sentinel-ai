"""
normalizer/universal.py
========================
Responsabilidad ÃšNICA: orquestar el pipeline de normalizaciÃ³n.

Este archivo es intencionalmente DELGADO. Solo coordina:
  1. Sanitizer      â†’ limpia la entrada
  2. SemanticExtractor â†’ extrae campos canÃ³nicos de cualquier JSON
  3. PatternClassifier â†’ clasifica el patrÃ³n de ataque
  4. _build_canonical  â†’ ensambla el schema final

No contiene lÃ³gica de extracciÃ³n ni de clasificaciÃ³n.
Si algo falla en una etapa, pasa a la siguiente con lo que tiene.

Schema canÃ³nico de salida (siempre presente, nunca falta una llave):
  source, asset_id, src_ip, severity_score, severity,
  event_type, pattern_hint, pattern_confidence,
  description, command, numeric_value,
  timestamp, parse_confidence, raw_hash, features_vector,
  threat_intel, ti_details
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone

from ..security.sanitizer   import sanitize
from .semantic_extractor  import extract
from .pattern_classifier  import classify

logger = logging.getLogger(__name__)


def normalize(raw: dict) -> dict:
    """
    Punto de entrada principal.
    Acepta cualquier dict JSON y devuelve el schema canÃ³nico.
    Nunca lanza excepciones.
    """
    try:
        return _pipeline(raw)
    except Exception as exc:
        logger.error(f"normalize: error inesperado â€” {exc}", exc_info=True)
        return _empty_canonical(raw, error=str(exc))



def _pipeline(raw: dict) -> dict:
    # Paso 1: Sanitizar (limpieza + desempaquetado de JSON embebido)
    clean = sanitize(raw)

    # Paso 2: Extraer campos canÃ³nicos semÃ¡nticamente
    extracted = extract(clean)

    # Paso 3: Clasificar patrÃ³n de ataque
    classify_text = " ".join(filter(None, [
        str(extracted.get("event_name") or ""),
        str(extracted.get("command") or ""),
        json.dumps(clean),  # incluir el objeto completo para no perder contexto
    ]))
    pattern_result = classify(
        text           = classify_text,
        severity_score = extracted["severity_score"],
        command        = str(extracted.get("command") or ""),
    )
    # Diagnostic log: Input snippet -> Detected Pattern
    logger.debug(f"CLASSIFY: text='{classify_text[:200]}...' â†’ pattern='{pattern_result.pattern}'")

    # Paso 4: Ensamblar schema canÃ³nico
    return _build_canonical(raw, clean, extracted, pattern_result)



def _build_canonical(raw: dict, clean: dict, extracted: dict, pattern) -> dict:
    score      = round(extracted["severity_score"], 3)
    asset_id   = extracted["asset_id"]
    timestamp  = _normalize_timestamp(extracted.get("timestamp_raw"))

    return {
        # IdentificaciÃ³n
        "source":             _detect_source_name(clean),
        "asset_id":           asset_id,
        "src_ip":             extracted["src_ip"],
        "external_event_id":  _make_id(raw),

        # ClasificaciÃ³n
        "severity":           _score_to_level(score),
        "severity_score":     score,
        "event_type":         str(extracted.get("event_name") or "unknown"),
        "pattern_hint":       pattern.pattern,
        "pattern_confidence": pattern.confidence,
        "description":        pattern.reason,
        "command":            extracted.get("command"),
        "numeric_value":      extracted.get("numeric_value"),

        # Temporalidad
        "timestamp":          timestamp,
        "received_at":        datetime.now(timezone.utc).isoformat(),

        # Calidad del parsing
        "parse_confidence":   extracted["parse_confidence"],

        # AuditorÃ­a
        "raw_hash": hashlib.sha256(
            json.dumps(raw, sort_keys=True).encode()
        ).hexdigest(),

        # ML â€” features_vector para IsolationForest
        "features_vector": {
            "severity_score":   score,
            "asset_value":      0.5,        # se actualiza en enricher
            "timestamp_delta":  0.0,        # se calcula en correlator
            "event_type_id":    (int(hashlib.md5(str(extracted.get("event_name") or "unknown").encode()).hexdigest()[:8], 16) % 1000) / 1000.0,
            "numeric_anomaly":  _numeric_to_feature(extracted.get("numeric_value")),
            "command_risk":     _command_to_feature(extracted.get("command")),
        },

        # Enriquecimiento (se completa en enricher)
        "threat_intel": False,
        "ti_details":   {},
    }


def _detect_source_name(obj: dict) -> str:
    """
    Identifica el nombre de la fuente por firmas Ãºnicas.
    Solo para etiquetado â€” la extracciÃ³n NO depende de esto.
    """
    if "rule" in obj and "agent" in obj:
        return "wazuh"
    if "eventSource" in obj and "awsRegion" in obj:
        return "aws_cloudtrail"
    if "aid" in obj and "ComputerName" in obj:
        return "crowdstrike"
    if "kind" in obj and str(obj.get("kind", "")).startswith("admin#reports"):
        return "google_workspace"
    if "Workload" in obj and "UserId" in obj and "AuditData" in obj:
        return "microsoft_365"
    if "StartTime" in obj and "LogSource" in obj and "Magnitude" in obj:
        return "qradar"
    if "occurredAt" in obj and ("clientMac" in obj or "apMac" in obj):
        return "meraki"
    if "topic" in obj and "d_id" in obj:
        return "iot_mqtt"
    if "verb" in obj and "objectRef" in obj and "user" in obj:
        return "kubernetes_audit"
    if "sensor" in obj or ("input" in obj and "session" in obj):
        return "honeypot"
    if "device" in obj and "dst_port" in obj:
        return "cisco_firewall"
    if "_time" in obj and "sourcetype" in obj:
        return "splunk"
    if "Severity" in obj and "IncidentNumber" in obj:
        return "microsoft_sentinel"
    return "unknown"


def _normalize_timestamp(ts) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    try:
        ts_str = str(ts).strip()
        
        # 1. Formato Compacto (YYYYMMDDHHMMSS)
        if len(ts_str) == 14 and ts_str.isdigit():
            return datetime.strptime(ts_str, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()

        # 2. Manejo de Timestamps Numéricos (Epochs)
        # Heurística de longitud:
        # - 10 dígitos: segundos (ej: 1712598313)
        # - 13 dígitos: milisegundos
        # - 16 dígitos: microsegundos
        # - 19 dígitos: nanosegundos
        clean_ts = ts_str.split('.')[0] # Ignorar decimales para el conteo
        if clean_ts.replace('-', '').isdigit():
            val = int(float(ts_str))
            l = len(str(abs(val)))
            
            if l >= 18:   # Nanosegundos
                val //= 1_000_000_000
            elif l >= 15: # Microsegundos
                val //= 1_000_000
            elif l >= 12: # Milisegundos
                val //= 1000
            # De lo contrario, se asume segundos
            
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()

        # 3. ISO Standard y variaciones
        return ts_str.replace("Z", "+00:00")
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _score_to_level(score: float) -> str:
    if score >= 0.85: return "critical"
    if score >= 0.65: return "high"
    if score >= 0.40: return "medium"
    return "low"


def _make_id(raw: dict) -> str:
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True).encode()
    ).hexdigest()[:24]


def _numeric_to_feature(value) -> float:
    """Convierte un valor numÃ©rico de sensor a feature 0â€“1 para el ML."""
    if value is None:
        return 0.0
    # Normalizar: valores > 1000 se comprimen con log
    import math
    v = float(value)
    if v <= 0:
        return 0.0
    return round(min(1.0, math.log10(v + 1) / 4.0), 4)


def _command_to_feature(command: str | None) -> float:
    """Convierte la peligrosidad del comando a feature 0â€“1 para el ML."""
    if not command:
        return 0.0
    cmd = command.lower()
    if any(x in cmd for x in ['miner', 'ransomware', 'nc -e', 'pty.spawn', 'mimikatz']):
        return 1.0
    if any(x in cmd for x in ['wget', 'curl', 'chmod +x', 'base64', '-enc', 'rm -rf']):
        return 0.8
    if any(x in cmd for x in ['powershell', 'cmd.exe', 'whoami', 'netstat', 'lsass']):
        return 0.6
    if any(x in cmd for x in ['ls', 'ps', 'id', 'uname', 'uptime']):
        return 0.2
    return 0.1


def _empty_canonical(raw: dict, error: str = "") -> dict:
    """Schema mÃ­nimo seguro cuando el pipeline falla completamente."""
    return {
        "source": "error", "asset_id": "unknown", "src_ip": None,
        "external_event_id": _make_id(raw),
        "severity": "low", "severity_score": 0.1,
        "event_type": "parse_error", "pattern_hint": "none",
        "pattern_confidence": 0.0,
        "description": f"Error en normalizaciÃ³n: {error}",
        "command": None, "numeric_value": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "parse_confidence": 0.0,
        "raw_hash": _make_id(raw),
        "features_vector": {
            "severity_score": 0.1, "asset_value": 0.5,
            "timestamp_delta": 0.0, "event_type_id": 0.0,
            "numeric_anomaly": 0.0, "command_risk": 0.0,
        },
        "threat_intel": False, "ti_details": {},
    }

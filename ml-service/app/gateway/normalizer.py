"""
Auto-Normalizador Universal
Detecta la fuente automáticamente por la estructura del JSON.
El usuario nunca declara qué SIEM tiene.
Cubre: Wazuh, Microsoft Sentinel, Splunk, Suricata, iptables/UFW,
       Cisco ASA, pfSense, AWS CloudTrail, formato GRC propio.
"""
import hashlib, json, re
from datetime import datetime


def auto_normalize(raw: dict) -> dict:
    """
    Punto de entrada único. Detecta y normaliza cualquier formato.
    Devuelve siempre los mismos 8 campos sin importar la fuente.
    """
    detector = _detect_source(raw)
    return detector(raw)


# ── Detección automática de fuente ────────────────────────────────────────────

def _detect_source(raw: dict) -> callable:
    """Elige el parser correcto basándose en la estructura del JSON."""

    # Wazuh — tiene 'rule' y 'agent'
    if "rule" in raw and "agent" in raw:
        return _parse_wazuh

    # Microsoft Sentinel — tiene 'Severity' e 'IncidentNumber'
    if "Severity" in raw and "IncidentNumber" in raw:
        return _parse_ms_sentinel

    # Suricata — tiene 'event_type' y 'alert'
    if "event_type" in raw and "alert" in raw:
        return _parse_suricata

    # Splunk — tiene 'result' o '_raw' típico de Splunk
    if "result" in raw or "_raw" in raw:
        return _parse_splunk

    # AWS CloudTrail — tiene 'eventSource' y 'awsRegion'
    if "eventSource" in raw and "awsRegion" in raw:
        return _parse_cloudtrail

    # Formato propio del GRC — tiene 'technical_id' y 'external_event_id'
    if "technical_id" in raw and "external_event_id" in raw:
        return _parse_grc_native

    # Syslog genérico — tiene 'message' o 'msg'
    if "message" in raw or "msg" in raw:
        return _parse_syslog

    # Firewall / iptables en texto — tiene 'SRC' y 'DST' como strings
    if "SRC" in raw or "src_ip" in raw:
        return _parse_firewall

    # Catch-all — intenta extraer lo que pueda
    return _parse_generic


# ── Parsers por fuente ─────────────────────────────────────────────────────────

WAZUH_LEVEL_MAP = {
    range(1, 4): 0.1, range(4, 7): 0.3,
    range(7, 10): 0.6, range(10, 13): 0.8, range(13, 16): 1.0
}

def _parse_wazuh(raw: dict) -> dict:
    level = raw.get("rule", {}).get("level", 0)
    score = next((v for r, v in WAZUH_LEVEL_MAP.items() if level in r), 0.3)
    return _build(
        source       = "wazuh",
        asset_id     = raw.get("agent", {}).get("name", "unknown"),
        src_ip       = raw.get("data", {}).get("srcip") or raw.get("data", {}).get("src_ip"),
        severity     = _level_to_severity(score),
        severity_score = score,
        event_type   = raw.get("rule", {}).get("description", "unknown"),
        description  = f"Wazuh nivel {level}: {raw.get('rule', {}).get('description', '')}",
        raw          = raw
    )

def _parse_ms_sentinel(raw: dict) -> dict:
    sev_map = {"Low": 0.2, "Medium": 0.5, "High": 0.8, "Critical": 1.0}
    score   = sev_map.get(raw.get("Severity", "Low"), 0.2)
    entity  = raw.get("Entities", [{}])[0] if raw.get("Entities") else {}
    return _build(
        source       = "microsoft_sentinel",
        asset_id     = entity.get("HostName", raw.get("WorkspaceId", "unknown")),
        src_ip       = entity.get("Address"),
        severity     = raw.get("Severity", "low").lower(),
        severity_score = score,
        event_type   = raw.get("Title", "unknown"),
        description  = raw.get("Description", raw.get("Title", "")),
        raw          = raw
    )

def _parse_suricata(raw: dict) -> dict:
    sev_map = {1: 1.0, 2: 0.7, 3: 0.4}
    alert   = raw.get("alert", {})
    score   = sev_map.get(alert.get("severity", 3), 0.4)
    return _build(
        source       = "suricata",
        asset_id     = raw.get("dest_ip", raw.get("hostname", "unknown")),
        src_ip       = raw.get("src_ip"),
        severity     = _level_to_severity(score),
        severity_score = score,
        event_type   = alert.get("category", "ids_alert"),
        description  = alert.get("signature", "Suricata IDS Alert"),
        raw          = raw
    )

def _parse_splunk(raw: dict) -> dict:
    result  = raw.get("result", raw)
    score   = _text_to_score(result.get("severity", result.get("urgency", "medium")))
    return _build(
        source       = "splunk",
        asset_id     = result.get("host", result.get("dest", "unknown")),
        src_ip       = result.get("src_ip", result.get("src", result.get("source_ip"))),
        severity     = result.get("severity", "medium"),
        severity_score = score,
        event_type   = result.get("type", result.get("sourcetype", "splunk_alert")),
        description  = result.get("message", result.get("search_name", "Splunk Alert")),
        raw          = raw
    )

def _parse_cloudtrail(raw: dict) -> dict:
    error   = raw.get("errorCode") or raw.get("errorMessage")
    score   = 0.7 if error else 0.3
    return _build(
        source       = "aws_cloudtrail",
        asset_id     = raw.get("requestParameters", {}).get("instanceId",
                       raw.get("resources", [{}])[0].get("ARN", "aws-resource")),
        src_ip       = raw.get("sourceIPAddress"),
        severity     = "high" if error else "low",
        severity_score = score,
        event_type   = raw.get("eventName", "aws_api_call"),
        description  = f"AWS {raw.get('eventSource','')}: {raw.get('eventName','')}",
        raw          = raw
    )

def _parse_grc_native(raw: dict) -> dict:
    """Formato nativo del GRC — el más común para clientes existentes."""
    score = _text_to_score(raw.get("severity", "medium"))
    return _build(
        source       = "grc_native",
        asset_id     = raw.get("technical_id", "unknown"),
        src_ip       = raw.get("raw_data", {}).get("srcip") if isinstance(raw.get("raw_data"), dict) else None,
        severity     = raw.get("severity", "medium"),
        severity_score = score,
        event_type   = raw.get("event_type", "other"),
        description  = raw.get("description", ""),
        raw          = raw
    )

def _parse_syslog(raw: dict) -> dict:
    msg   = str(raw.get("message", raw.get("msg", "")))
    score = _keyword_to_score(msg)
    return _build(
        source       = "syslog",
        asset_id     = raw.get("host", raw.get("hostname", raw.get("logsource", "unknown"))),
        src_ip       = raw.get("src_ip", _extract_ip(msg)),
        severity     = _level_to_severity(score),
        severity_score = score,
        event_type   = raw.get("program", raw.get("facility", "syslog")),
        description  = msg[:500],
        raw          = raw
    )

def _parse_firewall(raw: dict) -> dict:
    action = str(raw.get("action", raw.get("Action", "block"))).lower()
    score  = 0.6 if "block" in action or "deny" in action else 0.2
    return _build(
        source       = "firewall",
        asset_id     = raw.get("DST", raw.get("dst_ip", raw.get("dest", "unknown"))),
        src_ip       = raw.get("SRC", raw.get("src_ip")),
        severity     = "medium" if score >= 0.5 else "low",
        severity_score = score,
        event_type   = f"firewall_{action}",
        description  = f"Firewall {action.upper()} desde {raw.get('SRC', raw.get('src_ip', '?'))}",
        raw          = raw
    )

def _parse_generic(raw: dict) -> dict:
    """Catch-all — extrae lo que pueda de cualquier JSON."""
    text  = json.dumps(raw).lower()
    score = _keyword_to_score(text)
    return _build(
        source       = "unknown",
        asset_id     = raw.get("host", raw.get("hostname", raw.get("asset", raw.get("device", "unknown")))),
        src_ip       = raw.get("src_ip", raw.get("source_ip", raw.get("ip", _extract_ip(text)))),
        severity     = _level_to_severity(score),
        severity_score = score,
        event_type   = raw.get("type", raw.get("event_type", "generic")),
        description  = raw.get("message", raw.get("description", raw.get("msg", str(raw)[:300]))),
        raw          = raw
    )


# ── Schema de salida universal ────────────────────────────────────────────────

def _build(source, asset_id, src_ip, severity, severity_score,
           event_type, description, raw) -> dict:
    return {
        "source":          source,
        "asset_id":        str(asset_id or "unknown"),
        "src_ip":          src_ip,
        "severity":        severity,
        "severity_score":  round(float(severity_score), 3),
        "event_type":      str(event_type or "unknown"),
        "description":     str(description or "")[:500],
        "raw_hash":        hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest(),
        "timestamp":       datetime.utcnow().isoformat(),
        "threat_intel":    False,   # se rellena en el enricher
        "ti_details":      {}
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _text_to_score(text: str) -> float:
    return {"critical": 1.0, "high": 0.8, "medium": 0.5,
            "low": 0.2, "info": 0.1, "informational": 0.1}.get(
        str(text).lower(), 0.3)

def _level_to_severity(score: float) -> str:
    if score >= 0.8: return "critical"
    if score >= 0.6: return "high"
    if score >= 0.4: return "medium"
    return "low"

def _keyword_to_score(text: str) -> float:
    kw = {"critical": 1.0, "rootkit": 1.0, "malware": 0.9,
          "exploit": 0.9, "error": 0.6, "failed": 0.6,
          "denied": 0.5, "blocked": 0.5, "warning": 0.4,
          "warn": 0.4, "notice": 0.2, "info": 0.1}
    for k, v in kw.items():
        if k in text:
            return v
    return 0.2

def _extract_ip(text: str) -> str | None:
    m = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', text)
    return m.group(0) if m else None

"""
Normalizador Universal SIEM-Agnóstico v2.0
==========================================
Detecta el formato de log automáticamente por estructura y extrae
siempre los mismos campos canónicos sin importar la fuente.

Fuentes soportadas:
  1. Wazuh                  — rule + agent
  2. Microsoft Sentinel      — Severity + IncidentNumber
  3. Suricata (IDS/IPS)      — event_type + alert
  4. Splunk (JSON alert)     — result o _raw
  5. AWS CloudTrail          — eventSource + awsRegion
  6. Elastic ECS             — @timestamp + ecs.version
  7. CEF (Common Event Fmt)  — CEF:0| en el campo cef_raw o message
  8. LEEF (IBM QRadar)       — LEEF:2.0| en leef_raw o message
  9. Windows Event Log JSON  — EventID / EventCode + Channel
 10. CrowdStrike Falcon EDR  — detect_id o composite_id
 11. Zscaler Proxy           — app_class + urlCategory
 12. Syslog / texto genérico — message o msg
 13. Firewall (iptables/pfSense) — SRC + DST
 14. Formato GRC nativo      — technical_id + external_event_id
 15. Catch-all                — cualquier JSON desconocido

Campos canónicos de salida (siempre presentes):
  external_event_id  — ID único del evento (para deduplicación y auditoría)
  source             — nombre del SIEM/fuente detectado
  asset_id           — host/agente/activo afectado
  src_ip             — IP de origen del ataque
  severity           — low | medium | high | critical
  severity_score     — 0.0 a 1.0 para el modelo ML
  event_type         — tipo de evento normalizado
  pattern_hint       — pista de patrón de ataque (brute_force, lateral_movement, etc.)
  description        — descripción legible
  timestamp          — timestamp original del log (UTC ISO-8601)
  raw_hash           — SHA-256 del JSON original (para auditoría)
  threat_intel       — False (se rellena en enricher)
  ti_details         — {} (se rellena en enricher)
  features_vector    — vector de 4 dimensiones para el modelo IsolationForest
"""
import hashlib, json, re
from datetime import datetime, timezone


# ── Punto de entrada ──────────────────────────────────────────────────────────

def auto_normalize(raw: dict) -> dict:
    """
    Detecta la fuente del log y normaliza al schema canónico.
    Nunca lanza excepciones: un error en un parser produce un registro
    'unknown' en lugar de perder el evento.
    """
    try:
        parser = _detect_source(raw)
        result = parser(raw)
    except Exception as e:
        result = _parse_generic(raw)
        result["description"] = f"[Fallback parser] {e}: {result['description']}"
    return result


# ── Detección automática de fuente ────────────────────────────────────────────

def _detect_source(raw: dict):
    """
    Orden de detección: de más específico a más genérico.
    Cada condición usa campos ÚNICOS de cada plataforma.
    """
    # 1. Wazuh — 'rule' + 'agent' son exclusivos de Wazuh
    if "rule" in raw and "agent" in raw:
        return _parse_wazuh

    # 2. Microsoft Sentinel — IncidentNumber es exclusivo de MS Sentinel
    if "Severity" in raw and "IncidentNumber" in raw:
        return _parse_ms_sentinel

    # 3. Elastic ECS — ecs.version es la firma de ECS
    if "ecs" in raw or ("@timestamp" in raw and "event" in raw and "host" in raw):
        return _parse_elastic_ecs

    # 4. Suricata — event_type + alert es exclusivo de Suricata
    if "event_type" in raw and "alert" in raw:
        return _parse_suricata

    # 5. AWS CloudTrail — eventSource + awsRegion son exclusivos de CloudTrail
    if "eventSource" in raw and "awsRegion" in raw:
        return _parse_cloudtrail

    # 6. CrowdStrike Falcon — detect_id o composite_id son exclusivos
    if "detect_id" in raw or "composite_id" in raw or "falcon_host_link" in raw:
        return _parse_crowdstrike

    # 7. Windows Event Log JSON — EventID/EventCode + Channel
    if ("EventID" in raw or "EventCode" in raw) and ("Channel" in raw or "Provider" in raw):
        return _parse_windows_event

    # 8. Zscaler Proxy — app_class + urlCategory son exclusivos
    if "app_class" in raw or "urlCategory" in raw:
        return _parse_zscaler

    # 9. Splunk — result o _raw
    if "result" in raw or "_raw" in raw:
        return _parse_splunk

    # 10. CEF — formato CEF en campo cef_raw o message
    msg_str = str(raw.get("cef_raw", raw.get("message", raw.get("msg", ""))))
    if msg_str.startswith("CEF:"):
        return _parse_cef

    # 11. LEEF (IBM QRadar)
    if msg_str.startswith("LEEF:"):
        return _parse_leef

    # 12. Formato GRC nativo
    if "technical_id" in raw and "external_event_id" in raw:
        return _parse_grc_native

    # 13. Firewall / iptables — SRC/DST en mayúsculas o src_ip/dst_ip
    if "SRC" in raw or ("src_ip" in raw and "dst_ip" in raw and "action" in raw):
        return _parse_firewall

    # 14. Syslog genérico
    if "message" in raw or "msg" in raw:
        return _parse_syslog

    # 15. Catch-all
    return _parse_generic


# ── Parsers por fuente ────────────────────────────────────────────────────────

def _parse_wazuh(raw: dict) -> dict:
    """
    Wazuh JSON alert.
    Campos clave: rule.level (0-15), agent.id, agent.name,
                  data.srcip, rule.description, id (event id)
    """
    rule   = raw.get("rule", {})
    agent  = raw.get("agent", {})
    data   = raw.get("data", {})
    level  = int(rule.get("level", 0))

    # level 0-3: 0.1 | 4-6: 0.3 | 7-9: 0.6 | 10-12: 0.8 | 13-15: 1.0
    score = 0.1 if level < 4 else 0.3 if level < 7 else 0.6 if level < 10 else 0.8 if level < 13 else 1.0

    # external_event_id: el campo 'id' de Wazuh identifica la alerta
    ext_id = str(raw.get("id", raw.get("_id", "")))

    # src_ip: Wazuh lo guarda en data.srcip o data.src_ip o data.win.eventdata.ipAddress
    src_ip = (data.get("srcip") or data.get("src_ip") or
              data.get("win", {}).get("eventdata", {}).get("ipAddress") or
              _extract_ip(json.dumps(data)))

    # asset_id: Wazuh lo guarda en agent.name o agent.id, pero a veces viene en 'host' o 'data.agent'
    asset_id = (agent.get("name") or agent.get("id") or 
                raw.get("host", {}).get("name") or 
                data.get("agent", {}).get("name") or "unknown_asset")

    event_type = rule.get("description", "wazuh_alert")
    # Texto enriquecido para clasificación (incluye descripción completa + grupos de regla)
    classify_text = f"{event_type} {rule.get('groups', '')} {json.dumps(raw.get('data', {}))}"    
    pattern    = _classify_pattern(classify_text, level, src_ip)

    return _build(
        source          = "wazuh",
        external_event_id = ext_id or _make_id(raw),
        asset_id        = asset_id,
        src_ip          = src_ip,
        severity_score  = score,
        event_type      = event_type,
        pattern_hint    = pattern,
        description     = f"[Wazuh L{level}] {event_type}",
        timestamp_raw   = raw.get("timestamp"),
        raw             = raw,
    )


def _parse_ms_sentinel(raw: dict) -> dict:
    """
    Microsoft Sentinel incident JSON.
    Campos clave: Severity, IncidentNumber, Title, Entities[], AlertTime
    """
    sev_map = {"Informational": 0.1, "Low": 0.2, "Medium": 0.5,
               "High": 0.8, "Critical": 1.0}
    score   = sev_map.get(raw.get("Severity", "Low"), 0.2)

    # Entidades: extraer HostName e IPs
    entities = raw.get("Entities", [])
    hosts    = [e.get("HostName") for e in entities if e.get("HostName")]
    ips      = [e.get("Address")  for e in entities if e.get("Address")]

    asset_id = hosts[0] if hosts else raw.get("WorkspaceId", "unknown")
    src_ip   = ips[0]   if ips   else None

    event_type = raw.get("Title", "sentinel_incident")
    return _build(
        source            = "microsoft_sentinel",
        external_event_id = str(raw.get("IncidentNumber", _make_id(raw))),
        asset_id          = asset_id,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(event_type, score * 15, src_ip),
        description       = raw.get("Description", event_type)[:500],
        timestamp_raw     = raw.get("AlertTime"),
        raw               = raw,
    )


def _parse_elastic_ecs(raw: dict) -> dict:
    """
    Elastic Common Schema (ECS).
    Campos clave: @timestamp, event.{category,type,severity},
                  host.name, source.ip, rule.name
    """
    event  = raw.get("event",  {})
    host   = raw.get("host",   {})
    source = raw.get("source", {})
    rule   = raw.get("rule",   {})

    sev_text = str(event.get("severity", event.get("risk_score", "low")))
    score    = _text_to_score(sev_text) if not sev_text.isdigit() else min(int(sev_text) / 100, 1.0)

    event_type = (event.get("action") or event.get("category") or
                  rule.get("name") or "elastic_event")
    # Texto enriquecido: incluir message completo para detectar powershell/enc etc.
    classify_text = f"{event_type} {raw.get('message', '')} {rule.get('name', '')}"
    return _build(
        source            = "elastic_ecs",
        external_event_id = (raw.get("event", {}).get("id") or
                             raw.get("_id") or _make_id(raw)),
        asset_id          = host.get("name", host.get("hostname", "unknown")),
        src_ip            = source.get("ip"),
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(classify_text, score * 15, source.get("ip")),
        description       = raw.get("message", rule.get("description", event_type))[:500],
        timestamp_raw     = raw.get("@timestamp"),
        raw               = raw,
    )


def _parse_suricata(raw: dict) -> dict:
    """
    Suricata EVE JSON (IDS/IPS).
    Campos clave: event_type, alert.{severity,signature,category},
                  src_ip, dest_ip, timestamp
    """
    alert   = raw.get("alert", {})
    sev_map = {1: 1.0, 2: 0.7, 3: 0.4, 4: 0.2}
    score   = sev_map.get(int(alert.get("severity", 3)), 0.4)

    event_type = alert.get("category", alert.get("signature", "ids_alert"))
    return _build(
        source            = "suricata",
        external_event_id = str(raw.get("flow_id", _make_id(raw))),
        asset_id          = raw.get("dest_ip", raw.get("hostname", "unknown")),
        src_ip            = raw.get("src_ip"),
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(event_type, score * 15, raw.get("src_ip")),
        description       = alert.get("signature", "Suricata IDS Alert")[:500],
        timestamp_raw     = raw.get("timestamp"),
        raw               = raw,
    )


def _parse_cloudtrail(raw: dict) -> dict:
    """
    AWS CloudTrail.
    Campos clave: eventSource, eventName, awsRegion, sourceIPAddress,
                  errorCode, userIdentity, requestParameters
    """
    error = raw.get("errorCode") or raw.get("errorMessage")
    score = 0.8 if error else 0.3

    asset_id = (raw.get("requestParameters", {}).get("instanceId") or
                (raw.get("resources") or [{}])[0].get("ARN") or
                raw.get("recipientAccountId", "aws-resource"))

    event_type = raw.get("eventName", "aws_api_call")
    # Texto enriquecido: error code puede indicar fuerza bruta
    classify_text = f"{event_type} {error or ''} {raw.get('eventName','')}"    
    return _build(
        source            = "aws_cloudtrail",
        external_event_id = raw.get("eventID", _make_id(raw)),
        asset_id          = asset_id,
        src_ip            = raw.get("sourceIPAddress"),
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(classify_text, score * 15, raw.get("sourceIPAddress")),
        description       = f"AWS {raw.get('eventSource','')}: {event_type}" + (f" ERROR:{error}" if error else ""),
        timestamp_raw     = raw.get("eventTime"),
        raw               = raw,
    )


def _parse_crowdstrike(raw: dict) -> dict:
    """
    CrowdStrike Falcon EDR detection.
    Campos clave: detect_id, severity, device.hostname,
                  behaviors[].cmd_line, behaviors[].technique
    """
    sev_map = {1: 0.1, 2: 0.3, 3: 0.5, 4: 0.7, 5: 0.9}  # CS severity 1-5
    score   = sev_map.get(int(raw.get("severity", 3)), 0.5)

    device   = raw.get("device", {})
    behaviors = raw.get("behaviors", [{}])
    first_b  = behaviors[0] if behaviors else {}

    event_type = first_b.get("technique", first_b.get("objective", "falcon_detection"))
    return _build(
        source            = "crowdstrike",
        external_event_id = raw.get("detect_id", raw.get("composite_id", _make_id(raw))),
        asset_id          = device.get("hostname", device.get("device_id", "unknown")),
        src_ip            = device.get("external_ip", device.get("local_ip")),
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(event_type, score * 15, None),
        description       = first_b.get("description", f"CrowdStrike: {event_type}")[:500],
        timestamp_raw     = raw.get("created_timestamp", raw.get("last_behavior")),
        raw               = raw,
    )


def _parse_windows_event(raw: dict) -> dict:
    """
    Windows Event Log en formato JSON (Winlogbeat / NXLog / Sysmon).
    Campos clave: EventID/EventCode, Channel, Computer,
                  EventData, System.TimeCreated
    """
    event_id  = int(raw.get("EventID", raw.get("EventCode", 0)))
    channel   = raw.get("Channel", raw.get("log_name", "Security"))
    computer  = raw.get("Computer", raw.get("winlog", {}).get("computer_name", "unknown"))
    event_data = raw.get("EventData", raw.get("event_data", {}))

    # Mapeo de Event IDs críticos a severidad (basado en doc: mod4)
    critical_ids = {4625, 4648, 4697, 4698, 4720, 4740, 1102}  # failed logon, task, service...
    high_ids     = {4624, 4634, 4672, 4688, 4703, 7045}           # logon, privilege, process
    score = (0.8 if event_id in critical_ids else
             0.5 if event_id in high_ids else 0.2)

    src_ip     = (event_data.get("IpAddress") or
                  event_data.get("SourceNetworkAddress") or
                  _extract_ip(json.dumps(event_data)))
    # Construir texto completo para clasificación de patrón
    event_type     = f"windows_event_{event_id}"
    # Incluir EventData en el texto para que el clasificador pueda analizar cmd_line, tarea, etc.
    detection_text = f"{event_type} {json.dumps(event_data).lower()}"
    pattern        = _classify_pattern(detection_text, score * 15, src_ip)

    return _build(
        source            = "windows_event_log",
        external_event_id = str(raw.get("RecordNumber", _make_id(raw))),
        asset_id          = computer,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = pattern,
        description       = f"Windows {channel} EventID:{event_id} en {computer}",
        timestamp_raw     = raw.get("TimeCreated", raw.get("@timestamp")),
        raw               = raw,
    )


def _parse_zscaler(raw: dict) -> dict:
    """
    Zscaler Proxy logs (NSS Feed / CSV-JSON).
    Campos clave: user, url, action, app_class, urlCategory,
                  srcip (o clientip), dstip, timestamp
    """
    action = str(raw.get("action", raw.get("reason", "allow"))).lower()
    score  = 0.7 if "block" in action or "deny" in action else 0.3
    # Eleva si la categoría es sospechosa
    cat = str(raw.get("urlCategory", "")).lower()
    if any(x in cat for x in ["malware", "phish", "botnet", "exploit"]):
        score = max(score, 0.8)

    event_type = f"proxy_{action}_{cat}" if cat else f"proxy_{action}"
    src_ip     = raw.get("srcip", raw.get("clientip", raw.get("src_ip")))
    # Para Zscaler la acción es prioritaria: si bloquea, primero chequear blocked_attempt
    classify_text = f"{action} {event_type}"
    return _build(
        source            = "zscaler_proxy",
        external_event_id = str(raw.get("recordid", _make_id(raw))),
        asset_id          = raw.get("hostname", raw.get("machineHostname", "unknown")),
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(classify_text, score * 15, src_ip),
        description       = f"Zscaler {action.upper()} -> {raw.get('url','?')} ({cat})",
        timestamp_raw     = raw.get("datetime", raw.get("timestamp")),
        raw               = raw,
    )


def _parse_splunk(raw: dict) -> dict:
    """
    Splunk alert search result (JSON).
    Campos clave: result.{host,src_ip,severity,urgency,type,message}
    o directamente en root para webhooks de Splunk.
    """
    result = raw.get("result", raw)
    sev    = result.get("severity", result.get("urgency", "medium"))
    score  = _text_to_score(sev)

    src_ip = result.get("src_ip", result.get("src", result.get("source_ip")))
    event_type = result.get("type", result.get("sourcetype", "splunk_alert"))
    return _build(
        source            = "splunk",
        external_event_id = str(result.get("_serial", result.get("_cd", _make_id(raw)))),
        asset_id          = result.get("host", result.get("dest", "unknown")),
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(event_type, score * 15, src_ip),
        description       = result.get("message", result.get("search_name", "Splunk Alert"))[:500],
        timestamp_raw     = result.get("_time"),
        raw               = raw,
    )


def _parse_cef(raw: dict) -> dict:
    """
    CEF: Common Event Format (ArcSight, Fortinet, Check Point...).
    Formato: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    Puede venir en campo 'cef_raw', 'message' o 'msg'.
    """
    cef_str = str(raw.get("cef_raw", raw.get("message", raw.get("msg", ""))))
    # Parsear cabecera CEF con regex
    hdr = re.match(
        r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)",
        cef_str
    )
    if not hdr:
        return _parse_generic(raw)

    severity_cef = int(hdr.group(7))          # 0-10
    score        = round(severity_cef / 10, 2)
    name         = hdr.group(6)
    product      = hdr.group(3)
    ext          = hdr.group(8)

    # Parsear extensión key=value
    ext_pairs = dict(re.findall(r'(\w+)=((?:[^=\s]|\s(?!\w+=))+)', ext))
    src_ip    = ext_pairs.get("src", ext_pairs.get("srcAddress"))
    asset_id  = (ext_pairs.get("dvc") or ext_pairs.get("dhost") or
                 ext_pairs.get("dst") or raw.get("host", "unknown"))
    event_id  = ext_pairs.get("externalId", ext_pairs.get("cn1", _make_id(raw)))

    return _build(
        source            = f"cef_{product.lower().replace(' ','_')}",
        external_event_id = str(event_id),
        asset_id          = asset_id,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = name,
        pattern_hint      = _classify_pattern(name, severity_cef, src_ip),
        description       = f"[CEF/{product}] {name} — {ext[:200]}",
        timestamp_raw     = ext_pairs.get("rt") or raw.get("timestamp"),
        raw               = raw,
    )


def _parse_leef(raw: dict) -> dict:
    """
    LEEF: Log Event Extended Format (IBM QRadar).
    Formato: LEEF:2.0|Vendor|Product|Version|EventID|<tab>key=value...
    """
    leef_str = str(raw.get("leef_raw", raw.get("message", raw.get("msg", ""))))
    # Cabecera
    hdr = re.match(r"LEEF:[\d.]+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", leef_str, re.DOTALL)
    if not hdr:
        return _parse_generic(raw)

    vendor   = hdr.group(1)
    event_id = hdr.group(4)
    ext_str  = hdr.group(5)

    # LEEF usa tab o espacio como separador de pares clave=valor
    # Probar primero con tab y si no hay pares, intentar con espacio
    separators = ["\t", " "]
    pairs = {}
    for sep in separators:
        candidates = [p for p in ext_str.split(sep) if "=" in p]
        if len(candidates) > 1:
            pairs = {}
            for p in candidates:
                if "=" in p:
                    k, _, v = p.partition("=")
                    pairs[k.strip()] = v.strip()
            break
    if not pairs:
        # Ultimo intento: split por tabulacion literal
        for p in ext_str.split():
            if "=" in p:
                k, _, v = p.partition("=")
                pairs[k.strip()] = v.strip()

    sev_text = pairs.get("sev", pairs.get("severity", "medium"))
    score    = _text_to_score(sev_text) if not sev_text.isdigit() else min(int(sev_text) / 10, 1.0)
    src_ip   = pairs.get("src", pairs.get("srcip"))
    asset_id = pairs.get("dst", pairs.get("dstip", pairs.get("usrName", "unknown")))
    # Texto enriquecido para clasificación: event_id + msg del LEEF
    leef_msg = pairs.get("msg", pairs.get("message", ""))
    classify_text = f"{event_id} {leef_msg}".replace("_", " ")

    return _build(
        source            = f"leef_qradar_{vendor.lower()[:20]}",
        external_event_id = str(pairs.get("identRecordID", event_id or _make_id(raw))),
        asset_id          = asset_id,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_id or "qradar_event",
        pattern_hint      = _classify_pattern(classify_text, score * 10, src_ip),
        description       = f"[LEEF/{vendor}] {event_id} — {leef_msg}"[:500],
        timestamp_raw     = pairs.get("devTime") or pairs.get("rt"),
        raw               = raw,
    )


def _parse_grc_native(raw: dict) -> dict:
    """
    Formato nativo del GRC del usuario.
    Campos clave: technical_id, external_event_id, severity, event_type, description
    """
    score = _text_to_score(raw.get("severity", "medium"))
    raw_data = raw.get("raw_data", {})
    src_ip   = (raw_data.get("srcip") if isinstance(raw_data, dict)
                else _extract_ip(str(raw_data)))
    event_type = raw.get("event_type", "other")
    return _build(
        source            = "grc_native",
        external_event_id = str(raw.get("external_event_id", _make_id(raw))),
        asset_id          = raw.get("technical_id", "unknown"),
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(event_type, score * 15, src_ip),
        description       = raw.get("description", "")[:500],
        timestamp_raw     = raw.get("timestamp"),
        raw               = raw,
    )


def _parse_syslog(raw: dict) -> dict:
    """
    Syslog genérico (Linux auth.log, kern.log, syslog).
    Campos: message/msg, host/hostname, program/facility, timestamp
    Aplica regex para extraer usuario, IP y evento del mensaje.
    """
    msg      = str(raw.get("message", raw.get("msg", "")))
    score    = _keyword_to_score(msg)
    src_ip   = raw.get("src_ip", _extract_ip(msg))
    user     = _extract_syslog_user(msg)
    program  = raw.get("program", raw.get("facility", raw.get("appname", "syslog")))
    host     = raw.get("host", raw.get("hostname", raw.get("logsource", "unknown")))
    event_type = _classify_syslog_event(msg, program)

    return _build(
        source            = "syslog",
        external_event_id = _make_id(raw),
        asset_id          = host,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(msg, score * 15, src_ip),
        description       = msg[:500],
        timestamp_raw     = raw.get("timestamp", raw.get("@timestamp")),
        raw               = raw,
    )


def _parse_firewall(raw: dict) -> dict:
    """
    Logs de firewall: iptables, pfSense, Cisco ASA, paloalto.
    Campos: SRC/DST o src_ip/dst_ip, action/Action, proto/protocol
    """
    action = str(raw.get("action", raw.get("Action", "block"))).lower()
    score  = 0.6 if any(x in action for x in ["block", "deny", "drop", "reject"]) else 0.2
    src_ip = raw.get("SRC", raw.get("src_ip", raw.get("source_ip")))
    dst    = raw.get("DST", raw.get("dst_ip", raw.get("destination_ip", "unknown")))
    proto  = raw.get("PROTO", raw.get("protocol", "?"))
    dport  = raw.get("DPT", raw.get("dst_port", "?"))

    event_type = f"firewall_{action}"
    return _build(
        source            = "firewall",
        external_event_id = _make_id(raw),
        asset_id          = dst,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(event_type, score * 15, src_ip),
        description       = f"Firewall {action.upper()} {proto} {src_ip}→{dst}:{dport}",
        timestamp_raw     = raw.get("timestamp"),
        raw               = raw,
    )


def _parse_generic(raw: dict) -> dict:
    """
    Catch-all: extrae lo que pueda de cualquier JSON desconocido.
    """
    text       = json.dumps(raw).lower()
    score      = _keyword_to_score(text)
    src_ip     = raw.get("src_ip", raw.get("source_ip", raw.get("ip", _extract_ip(text))))
    asset_id   = (raw.get("host") or raw.get("hostname") or raw.get("device") or
                  raw.get("asset") or raw.get("asset_id") or "unknown")
    event_type = raw.get("type", raw.get("event_type", raw.get("eventType", "unknown")))
    description = raw.get("message", raw.get("description", raw.get("msg", str(raw)[:300])))

    return _build(
        source            = "unknown",
        external_event_id = raw.get("id", raw.get("event_id", _make_id(raw))),
        asset_id          = asset_id,
        src_ip            = src_ip,
        severity_score    = score,
        event_type        = event_type,
        pattern_hint      = _classify_pattern(str(event_type), score * 15, src_ip),
        description       = str(description)[:500],
        timestamp_raw     = raw.get("timestamp", raw.get("@timestamp")),
        raw               = raw,
    )


# ── Schema de salida canónico ─────────────────────────────────────────────────

def _build(source, external_event_id, asset_id, src_ip,
           severity_score, event_type, pattern_hint,
           description, timestamp_raw, raw) -> dict:
    """
    Construye el objeto canónico que recibe el enricher, correlator y model.
    features_vector: los 4 números que alimentan al Isolation Forest.
    """
    score = round(float(severity_score), 3)

    # Timestamp original del log (no el de llegada a Sentinel)
    ts_original = _parse_timestamp(timestamp_raw) if timestamp_raw else datetime.now(timezone.utc).isoformat()

    return {
        # Identificación
        "source":           source,
        "external_event_id": str(external_event_id or _make_id(raw)),
        "asset_id":         str(asset_id or "unknown"),
        "src_ip":           src_ip,
        # Clasificación
        "severity":         _score_to_level(score),
        "severity_score":   score,
        "event_type":       str(event_type or "unknown"),
        "pattern_hint":     str(pattern_hint or "none"),
        "description":      str(description or "")[:500],
        # Temporalidad
        "timestamp":        ts_original,
        "received_at":      datetime.now(timezone.utc).isoformat(),
        # Auditoría
        "raw_hash":         hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest(),
        # ML
        "features_vector": {
            "severity_score":  score,
            "asset_value":     0.5,           # se actualiza en enricher si hay registro
            "timestamp_delta": 0.0,           # se calcula en correlator con historial Redis
            "event_type_id":   abs(hash(str(event_type))) % 1000 / 1000,
        },
        # Enriquecimiento (se completa en enricher)
        "threat_intel": False,
        "ti_details":   {},
    }


# ── Helpers internos ──────────────────────────────────────────────────────────

def _classify_pattern(event_text: str, level_num: float, src_ip) -> str:
    """
    Identifica patrones de ataque basado en la documentación (Módulos 3 y 4).
    Agnóstico al SIEM: analiza texto libre, event_type y Event IDs de Windows.
    Orden: de más específico a más genérico para evitar falsos positivos.
    """
    txt = str(event_text).lower()

    # ── Windows Event IDs directos (Módulo 4 — hunting lateral movement)
    # EventID 4625 = Failed Logon | 4740 = Account Locked
    if any(x in txt for x in ["event_4625", "event_4740", "eventid: 4625",
                                "failurereason", "bad password",
                                "unknown user name or bad password"]):
        return "brute_force_attempt"

    # EventID 4698 = Scheduled Task Created | 4697 = Service Installed
    if any(x in txt for x in ["event_4698", "event_4697", "scheduled task",
                                "schtask", "taskname", "taskcontent",
                                "persistence", "run key"]):
        return "persistence"

    # EventID 4624 Logon Type 10 = RDP
    if any(x in txt for x in ["event_4624", "logon type 10", "remotenetworkdrive",
                                "logon_type\':\'10\'", "\"logontype\": 10",
                                "lateral", "rdp", "remote desktop",
                                "wmic", "psexec", "admin$"]):
        return "lateral_movement"

    # Credenciales fallidas / brute force (texto libre — múltiples fuentes)
    if any(x in txt for x in ["failed password", "failed login", "authentication failure",
                                "invalid user", "logon failure", "authentication failed",
                                "multiple failed", "failed ssh", "ssh login fail",
                                "failed attempts", "repeated failed", "brute",
                                "incorrect password", "wrong password",
                                "failed authentication", "failed mfa", "mfa failed",
                                "no response from mfa"]):
        return "brute_force_attempt"

    # Login exitoso después de fallos
    if any(x in txt for x in ["accepted password", "accepted publickey",
                                "successful login", "logon success"]):
        return "successful_login"

    # Ejecución sospechosa (PowerShell, cmd, herramientas de post-explotación)
    if any(x in txt for x in ["powershell", "cmd.exe", "base64", "-enc",
                                "-encodedcommand", "wscript", "cscript",
                                "rundll32", "mshta", "regsvr32",
                                "credential dump", "lsass", "mimikatz",
                                "comsvcs", "minidump"]):
        return "suspicious_execution"

    # Exfiltración
    if any(x in txt for x in ["exfil", "dropbox", "onedrive", "large transfer",
                                "file sharing", "bytes_out", "upload"]):
        return "data_exfiltration"

    # Reconocimiento / escaneo
    if any(x in txt for x in ["port scan", "nmap", "syn flood", "sweep",
                                "reconnaissance", "probe", "network scan"]):
        return "reconnaissance"

    # Firewall / bloqueo — ANTES que malware para que Zscaler "blocked" no sea c2_beacon
    if any(x in txt for x in ["block", "blocked", "deny", "drop", "reject",
                                "firewall", "traffic forward deny"]):
        return "blocked_attempt"

    # C2 / Beaconing
    if any(x in txt for x in ["c2", "beacon", "command and control",
                                "cobaltstrike", "asyncrat", "reverse shell",
                                "malware"]):
        return "c2_beacon"

    # Fallback por severidad alta
    if level_num >= 10:
        return "high_severity_event"

    return "none"


def _classify_syslog_event(msg: str, program: str) -> str:
    """Normaliza el tipo de evento de syslog al schema interno."""
    m = msg.lower()
    p = str(program).lower()
    if "sshd" in p or "ssh" in p:
        if "failed" in m or "invalid" in m:
            return "ssh_failed_login"
        if "accepted" in m:
            return "ssh_successful_login"
        if "disconnect" in m:
            return "ssh_disconnect"
        return "ssh_event"
    if "sudo" in p:
        return "sudo_command"
    if "kernel" in p or "iptables" in p or "ufw" in p:
        return "kernel_firewall"
    if "cron" in p:
        return "cron_job"
    if "apache" in p or "nginx" in p:
        return "web_server"
    return f"syslog_{p}"


def _extract_syslog_user(msg: str) -> str | None:
    """Extrae el usuario de un mensaje syslog."""
    m = re.search(r'for (?:invalid user )?(\S+) from', msg)
    return m.group(1) if m else None


def _text_to_score(text: str) -> float:
    return {"critical": 1.0, "high": 0.8, "medium": 0.5,
            "low": 0.2, "info": 0.1, "informational": 0.1,
            "unknown": 0.3}.get(str(text).lower(), 0.3)


def _keyword_to_score(text: str) -> float:
    """Analiza el texto libre para estimar severidad."""
    t = text.lower()
    if any(x in t for x in ["rootkit", "ransomware", "critical", "exploit"]):
        return 1.0
    if any(x in t for x in ["malware", "backdoor", "trojan", "breach"]):
        return 0.9
    if any(x in t for x in ["failed password", "brute force", "intrusion", "attack"]):
        return 0.7
    if any(x in t for x in ["error", "failed", "denied", "blocked", "reject"]):
        return 0.5
    if any(x in t for x in ["warning", "warn", "suspicious"]):
        return 0.4
    if any(x in t for x in ["notice", "info", "accepted"]):
        return 0.2
    return 0.2


def _score_to_level(score: float) -> str:
    if score >= 0.8: return "critical"
    if score >= 0.6: return "high"
    if score >= 0.4: return "medium"
    return "low"


def _extract_ip(text: str) -> str | None:
    m = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', text)
    return m.group(0) if m else None


def _parse_timestamp(ts) -> str:
    """Normaliza cualquier formato de timestamp a UTC ISO-8601."""
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    ts_str = str(ts)
    # Ya es ISO-8601
    if re.match(r'\d{4}-\d{2}-\d{2}T', ts_str):
        return ts_str.replace("Z", "+00:00")
    # Syslog: Jun 13 12:22:01
    m = re.match(r'(\w{3})\s+(\d+)\s+(\d+:\d+:\d+)', ts_str)
    if m:
        year = datetime.now().year
        return f"{year}-{m.group(1)}-{m.group(2).zfill(2)}T{m.group(3)}+00:00"
    # Epoch Unix
    if re.match(r'^\d{10,13}$', ts_str):
        epoch = int(ts_str[:10])
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    return ts_str


def _make_id(raw: dict) -> str:
    """Genera un ID determinístico del evento cuando no viene en el log."""
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:24]

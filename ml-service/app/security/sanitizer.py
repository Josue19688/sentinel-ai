"""
security/sanitizer.py
=====================
Responsabilidad ÚNICA: limpiar y validar cualquier entrada antes de procesarla.

Reglas:
  - Truncar strings largos para evitar DoS
  - Eliminar caracteres de control / null bytes
  - Detectar y rechazar payloads que intenten inyección (JSON injection, path traversal)
  - Limitar profundidad y tamaño de objetos anidados
  - Desempaquetar strings que contengan JSON embebido (ej: M365 AuditData)
"""

import re
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Límites de seguridad ──────────────────────────────────────────────────────
MAX_STRING_LENGTH  = 2_000      # caracteres por campo string
MAX_OBJECT_DEPTH   = 10         # niveles de anidamiento permitidos
MAX_OBJECT_KEYS    = 200        # llaves totales por objeto
MAX_ARRAY_LENGTH   = 10_000     # elementos por array
MAX_PAYLOAD_BYTES  = 10_485_760 # 10 MB total

# Patrones que indican intento de inyección
_INJECTION_PATTERNS = [
    re.compile(r'\.\./'),                         # path traversal
    re.compile(r'<script', re.IGNORECASE),        # XSS básico
    re.compile(r'\$\{.*\}'),                      # template injection
    re.compile(r'__proto__', re.IGNORECASE),      # prototype pollution
    re.compile(r'constructor\s*\[', re.IGNORECASE),
]


# ── Punto de entrada principal ────────────────────────────────────────────────

def sanitize(raw: Any, _depth: int = 0) -> Any:
    """
    Limpia recursivamente cualquier valor.
    Devuelve el valor limpio. Nunca lanza excepciones: en caso de error
    devuelve una representación segura del objeto problemático.
    """
    if _depth > MAX_OBJECT_DEPTH:
        logger.warning("sanitize: profundidad máxima alcanzada, truncando rama")
        return "[truncado: demasiado anidado]"

    if isinstance(raw, dict):
        return _sanitize_dict(raw, _depth)
    if isinstance(raw, list):
        return _sanitize_list(raw, _depth)
    if isinstance(raw, str):
        return _sanitize_string(raw)
    if isinstance(raw, (int, float, bool)) or raw is None:
        return raw  # tipos escalares son seguros por sí mismos

    # Tipo desconocido: convertir a string y sanitizar
    return _sanitize_string(str(raw))


def validate_payload_size(raw_bytes: bytes) -> bool:
    """Devuelve True si el payload está dentro del límite permitido."""
    return len(raw_bytes) <= MAX_PAYLOAD_BYTES


def unwrap_embedded_json(value: str) -> Any:
    """
    Si un string contiene JSON válido embebido (como M365 AuditData),
    lo parsea y devuelve el objeto. Si no, devuelve el string original.

    Caso de uso: {"AuditData": "{\"Role\":\"GlobalAdmin\"}"}
    """
    stripped = value.strip()
    if not (stripped.startswith('{') or stripped.startswith('[')):
        return value
    try:
        parsed = json.loads(stripped)
        logger.debug("unwrap_embedded_json: JSON embebido desempaquetado")
        return parsed
    except (json.JSONDecodeError, ValueError):
        return value


# ── Sanitizadores por tipo ────────────────────────────────────────────────────

def _sanitize_dict(obj: dict, depth: int) -> dict:
    if len(obj) > MAX_OBJECT_KEYS:
        logger.warning(f"sanitize: objeto con {len(obj)} llaves, truncando a {MAX_OBJECT_KEYS}")
        obj = dict(list(obj.items())[:MAX_OBJECT_KEYS])

    result = {}
    for key, value in obj.items():
        clean_key = _sanitize_string(str(key), max_len=200)

        # Desempaquetar JSON embebido en strings antes de sanitizar
        if isinstance(value, str):
            value = unwrap_embedded_json(value)

        result[clean_key] = sanitize(value, depth + 1)

    return result


def _sanitize_list(arr: list, depth: int) -> list:
    if len(arr) > MAX_ARRAY_LENGTH:
        logger.warning(f"sanitize: array con {len(arr)} elementos, truncando a {MAX_ARRAY_LENGTH}")
        arr = arr[:MAX_ARRAY_LENGTH]
    return [sanitize(item, depth + 1) for item in arr]


def _sanitize_string(s: str, max_len: int = MAX_STRING_LENGTH) -> str:
    # 1. Eliminar null bytes y caracteres de control (excepto \n \t)
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)

    # 2. Detectar patrones de inyección
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(s):
            logger.warning(f"sanitize: patrón de inyección detectado, neutralizando: {s[:80]}")
            s = pattern.sub('[REDACTED]', s)

    # 3. Truncar strings demasiado largos
    if len(s) > max_len:
        s = s[:max_len] + '[...]'

    return s

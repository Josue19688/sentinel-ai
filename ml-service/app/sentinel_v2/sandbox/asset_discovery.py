"""
sandbox/asset_discovery.py
===========================
Responsabilidad ÚNICA: dado un DataFrame con logs aplanados,
encontrar la columna que mejor representa el identificador del activo.

El problema:
  Cada SIEM usa un nombre diferente para el mismo concepto:
    Wazuh       → agent.name  (después de flatten: agent_name)
    CrowdStrike → ComputerName
    AWS         → requestParameters.instanceId
    Cisco       → device
    Honeypot    → sensor
    Meraki      → clientMac
    K8s         → user.username

  Un loop genérico sobre columnas produce resultados incorrectos:
  Meraki tenía "description" antes que "clientMac" → asset = "Client associated"

Solución:
  Lista de prioridad explícita + validación de que el valor
  parece un identificador (longitud corta, no una frase).

Extensión:
  Para agregar soporte a un nuevo SIEM, agrega su campo
  de asset a ASSET_PRIORITY en la posición correcta.
  No necesitas tocar ningún otro módulo.
"""

import re
import logging
import pandas as pd

logger = logging.getLogger(__name__)


# ── Lista de prioridad de columnas de asset ───────────────────────────────────
# Orden: identificadores de máquina primero, usuarios al final,
# descripciones de evento NUNCA (no están en la lista).

ASSET_PRIORITY = [
    # Identificadores de hostname / máquina física
    "computername", "hostname", "host", "agent_name", "machine",

    # AWS CloudTrail — activo real está en requestParameters
    "requestparameters_instanceid",            # EC2
    "requestparameters_dbinstanceidentifier",  # RDS
    "requestparameters_bucketname",            # S3
    "requestparameters_username",              # IAM
    "requestparameters_functionname",          # Lambda

    # Identificadores de dispositivo de red
    "device",        # Cisco firewall
    "sensor",        # Honeypot (hp-guate-01)
    "device_id", "d_id", "sensor_id", "node", "asset_id",

    # SIEMs con campo de fuente explícito
    "logsource", "logsource",   # QRadar LogSource / Splunk host

    # Identificadores de red (cuando no hay hostname)
    "clientmac", "mac", "clientip",

    # Identificadores de usuario/actor (menor prioridad — puede ser el atacante)
    "userid", "user_username",

    # Google Workspace — actor puede ser atacante externo, se maneja aparte
    "actor_email",

    # Fallback: IP de origen
    "sourceipaddress", "endpoint",
]

# Regex para detectar IPv4 (usado en fallback)
_RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Longitud máxima de un identificador válido (IPs, MACs, hostnames, emails)
_MAX_IDENTIFIER_LEN = 80


# ── Aplanamiento recursivo ────────────────────────────────────────────────────

def flatten(obj: dict, prefix: str = "", sep: str = "_", max_depth: int = 3) -> dict:
    """
    Aplana un dict anidado en un solo nivel.

    {'user': {'username': 'admin'}} → {'user_username': 'admin'}
    {'events': [{'name': 'login'}]} → {'events_0_name': 'login'}

    max_depth previene explosión de columnas en objetos muy anidados.
    """
    result = {}
    for k, v in obj.items():
        new_key = f"{prefix}{sep}{k}" if prefix else k
        current_depth = len(new_key.split(sep))

        if isinstance(v, dict) and current_depth <= max_depth:
            result.update(flatten(v, new_key, sep, max_depth))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            # Arrays de dicts: tomar solo el primer elemento
            result.update(flatten(v[0], f"{new_key}_0", sep, max_depth))
        else:
            result[new_key] = v

    return result


# ── Descubrimiento de columna de asset ───────────────────────────────────────

def find_asset_column(df: pd.DataFrame) -> str | None:
    """
    Busca en el DataFrame la columna que mejor representa el asset_id.

    Estrategia:
      1. Normaliza nombres de columnas a lowercase
      2. Recorre ASSET_PRIORITY en orden
      3. Para cada candidato: valida que los valores sean identificadores cortos
      4. Si ninguno funciona: busca columna con valores que parezcan IPs

    Retorna el nombre REAL de la columna (con su case original) o None.
    """
    # Mapa: lowercase_normalizado → nombre_original_con_case
    cols_lower = {
        c.lower().replace("-", "_"): c
        for c in df.columns
    }

    for hint in ASSET_PRIORITY:
        hint_norm = hint.lower().replace("-", "_")
        if hint_norm not in cols_lower:
            continue

        col = cols_lower[hint_norm]
        sample = df[col].dropna().astype(str).head(10)

        if len(sample) == 0:
            continue

        avg_len = sample.str.len().mean()
        if avg_len <= _MAX_IDENTIFIER_LEN:
            logger.debug(f"asset_discovery: columna elegida → {col} (avg_len={avg_len:.0f})")
            return col

    # Fallback: buscar columna cuyos valores parezcan IPs
    for col in df.columns:
        if df[col].dtype != object:
            continue
        sample = df[col].dropna().astype(str).head(5)
        if sample.apply(lambda v: bool(_RE_IPV4.match(v))).any():
            logger.debug(f"asset_discovery: fallback IP → columna {col}")
            return col

    logger.warning("asset_discovery: no se encontró columna de asset — usando 'unknown_asset'")
    return None


# ── Resolución del asset para Google Workspace ───────────────────────────────

def resolve_google_asset(df: pd.DataFrame, asset_col: str) -> pd.Series:
    """
    Google Workspace: actor_email puede ser el atacante externo.
    Si el actor tiene dominio externo (gmail, hotmail, 'attacker', 'hacker'),
    usamos el valor del parámetro del evento como asset en su lugar.

    Esto evita que "attacker@external.com" aparezca como el activo afectado.
    """
    external_mask = df[asset_col].astype(str).str.contains(
        r"external|hacker|attacker|gmail\.com|hotmail|yahoo",
        case=False, na=False, regex=True,
    )

    if not external_mask.any():
        return df[asset_col].astype(str)

    # Buscar columna con el recurso afectado (parámetro del evento)
    param_col = next(
        (c for c in df.columns
         if "parameters" in c.lower() and "value" in c.lower()),
        None,
    )

    if param_col:
        resolved = df[param_col].fillna(df[asset_col]).astype(str)
        logger.info("asset_discovery: Google WS — actor externo detectado, usando parámetro del evento")
        return resolved

    return df[asset_col].astype(str)

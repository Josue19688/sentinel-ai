"""
Enricher — Inteligencia de Amenazas Automática
El usuario no configura nada. Sentinel consulta feeds públicos
y enriquece cada evento automáticamente.

Fuentes:
- AbuseIPDB (IPs maliciosas conocidas)
- Lista local de IPs/rangos bloqueados (actualizada periódicamente)
- Cache en Redis para no repetir consultas (TTL: 1 hora)
"""
import logging
import ipaddress
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

# IPs privadas — nunca se consultan en feeds externos
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Lista local básica de IPs conocidas maliciosas (se actualiza semanalmente)
# En producción esto se carga desde un feed externo
LOCAL_BLOCKLIST = set()


async def enrich(normalized: dict) -> dict:
    """
    Enriquece el evento normalizado con threat intelligence.
    Si no hay IP o es privada, retorna el evento sin cambios.
    """
    src_ip = normalized.get("src_ip")

    if not src_ip or _is_private(src_ip):
        return normalized

    # Consultar cache primero (Redis)
    cached = await _get_cache(src_ip)
    if cached is not None:
        normalized["threat_intel"] = cached["malicious"]
        normalized["ti_details"]   = cached
        return normalized

    # Verificar lista local
    if src_ip in LOCAL_BLOCKLIST:
        result = {"malicious": True, "source": "local_blocklist", "confidence": 90}
        await _set_cache(src_ip, result)
        normalized["threat_intel"] = True
        normalized["ti_details"]   = result
        return normalized

    # Consultar AbuseIPDB si hay API key configurada (ABUSEIPDB_API_KEY en .env)
    abuseipdb_key = settings.ABUSEIPDB_API_KEY or None
    if abuseipdb_key:
        result = await _check_abuseipdb(src_ip, abuseipdb_key)
        await _set_cache(src_ip, result)
        normalized["threat_intel"] = result["malicious"]
        normalized["ti_details"]   = result
        return normalized

    # Sin API key — verificar contra ipinfo gratuito (sin límite estricto)
    result = await _check_ipinfo(src_ip)
    await _set_cache(src_ip, result)
    normalized["threat_intel"] = result.get("malicious", False)
    normalized["ti_details"]   = result

    return normalized


async def _check_abuseipdb(ip: str, api_key: str) -> dict:
    """Consulta AbuseIPDB — detecta IPs con historial de abuso."""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30}
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "malicious":  score >= 25,
                    "source":     "abuseipdb",
                    "confidence": score,
                    "country":    data.get("countryCode"),
                    "isp":        data.get("isp"),
                    "reports":    data.get("totalReports", 0)
                }
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
    return {"malicious": False, "source": "abuseipdb_error"}


async def _check_ipinfo(ip: str) -> dict:
    """Geolocalización básica con ipinfo.io — gratuito sin key."""
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            r = await client.get(f"https://ipinfo.io/{ip}/json")
            if r.status_code == 200:
                data = r.json()
                # IPs de países con alto riesgo o en rangos de datacenter
                is_datacenter = "cloud" in str(data.get("org", "")).lower()
                return {
                    "malicious": False,  # ipinfo no da score de malicia
                    "source":    "ipinfo",
                    "country":   data.get("country"),
                    "org":       data.get("org"),
                    "datacenter": is_datacenter
                }
    except Exception as e:
        logger.warning(f"ipinfo lookup failed for {ip}: {e}")
    return {"malicious": False, "source": "none"}


from app.db import get_redis
import json

async def _get_cache(ip: str) -> dict | None:
    """Cache en Redis — TTL 1 hora para no repetir consultas."""
    try:
        r = await get_redis()
        val = await r.get(f"ti:{ip}")
        if val:
            return json.loads(val)
    except Exception:
        pass
    return None


async def _set_cache(ip: str, result: dict):
    try:
        r = await get_redis()
        await r.setex(f"ti:{ip}", 3600, json.dumps(result))
    except Exception:
        pass


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in PRIVATE_RANGES)
    except ValueError:
        return True

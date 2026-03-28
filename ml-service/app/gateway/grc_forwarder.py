"""
GRC Forwarder — Reenvío automático al GRC del cliente.
Usa el mismo contrato que ya tiene el GRC (X-API-Key / X-API-Secret).
El SIEM nunca sabe que Sentinel existe — solo ve que su alerta llegó al GRC.
"""
import httpx, logging, time, hashlib, secrets

logger = logging.getLogger(__name__)


async def forward_to_grc(client: dict, result: dict, original: dict) -> bool:
    """
    Reenvía el evento enriquecido al GRC del cliente.
    Usa el mismo formato que el GRC ya espera — sin cambios en el GRC.
    """
    grc_url    = client.get("grc_url")
    api_key    = client.get("grc_api_key")
    api_secret = client.get("grc_api_secret")

    if not grc_url:
        return False

    # Construir payload compatible con el contrato del GRC existente
    # Mantiene todos los campos originales + agrega los de Sentinel
    payload = {
        # Campos originales que el GRC ya entiende
        "external_event_id": original.get("external_event_id",
                             f"snl_{secrets.token_hex(8)}"),
        "technical_id":      original.get("technical_id",
                             original.get("agent", {}).get("name", "unknown"))
                             if isinstance(original.get("agent"), dict)
                             else original.get("technical_id", "unknown"),
        "source":            f"Sentinel-ML [{original.get('source', 'unknown')}]",
        "event_type":        result.get("pattern", "other"),
        "severity":          _risk_to_severity(result["risk_level"]),
        "description":       result["reason"],

        # Campos adicionales de Sentinel — el GRC puede usarlos o ignorarlos
        "sentinel_risk_level":   result["risk_level"],
        "sentinel_pattern":      result["pattern"],
        "sentinel_action":       result["action"],
        "sentinel_enriched":     result.get("enriched", False),
        "raw_data":              original
    }

    try:
        async with httpx.AsyncClient(timeout=5) as http:
            r = await http.post(
                f"{grc_url.rstrip('/')}/api/v1/integrations/telemetry",
                json=payload,
                headers={
                    "X-API-Key":    api_key,
                    "X-API-Secret": api_secret,
                    "Content-Type": "application/json",
                    "X-Forwarded-By": "Sentinel-ML/1.0"
                }
            )
            if r.status_code in (200, 201, 202):
                logger.info(f"GRC notified successfully — risk: {result['risk_level']}")
                return True
            else:
                logger.warning(f"GRC returned {r.status_code}: {r.text[:200]}")
                return False
    except Exception as e:
        logger.error(f"GRC forward failed: {e}")
        return False


def _risk_to_severity(risk_level: str) -> str:
    """Convierte el nivel de riesgo de Sentinel a la severidad que el GRC entiende."""
    return {"high": "critical", "medium": "high", "low": "low"}.get(risk_level, "medium")

"""
GRC Forwarder v2.0 — Envío de telemetría enriquecida con métricas de riesgo.
==============================================================================
Fase 2: ahora además de reenviar el evento, incluye el payload de riesgo
cuantitativo (ARO, ALE, EF, control ISO 27001) calculado por el RiskEngine.

El GRC recibe dos tipos de información en el mismo request:
  1. Los datos del evento normalizado (qué pasó, dónde, cuándo)
  2. Las métricas financieras del riesgo (cuánto impacta económicamente)
"""
import httpx, logging, time, hashlib, secrets
from app.risk_engine import RiskEngine
from app.config import settings

logger = logging.getLogger(__name__)

# Instancia compartida del motor de riesgo (síncrono — seguro para uso en async)
_risk_engine = RiskEngine(db_url=settings.DATABASE_URL)


async def forward_to_grc(client: dict, result: dict, normalized: dict) -> bool:
    """
    Reenvía el evento + métricas de riesgo al GRC del cliente.

    Args:
        client:     Datos del cliente Sentinel (url, api_key, api_secret)
        result:     Resultado del análisis (risk_level, pattern, reason...)
        normalized: Evento ya normalizado por auto_normalize()

    Returns:
        True si el GRC respondió 2xx, False en caso contrario.
    """
    grc_url    = client.get("grc_url")
    api_key    = client.get("grc_api_key")
    api_secret = client.get("grc_api_secret")

    if not grc_url:
        return False

    asset_id    = normalized.get("asset_id", "unknown")
    pattern     = normalized.get("pattern_hint", "none")
    client_id   = client.get("sentinel_key", "unknown")
    asset_value = normalized.get("features_vector", {}).get("asset_value", 0.5)

    # ── Calcular métricas de riesgo cuantitativo (Fase 2) ─────────────────
    risk_payload = {}
    try:
        risk_payload = _risk_engine.calculate_risk_for_asset(
            client_id   = client_id,
            asset_id    = asset_id,
            pattern     = pattern,
            window_days = 30,
            asset_value = float(asset_value),
        )
    except Exception as e:
        logger.warning(f"GRCForwarder: RiskEngine falló para {asset_id}: {e}")
        # No interrumpir el forward — enviar sin métricas si el engine falla

    # ── Construir payload final para el GRC ───────────────────────────────
    payload = _build_telemetry_payload(
        normalized   = normalized,
        result       = result,
        client_id    = client_id,
        risk_payload = risk_payload,
    )

    # ── Enviar al endpoint del GRC ────────────────────────────────────────
    return await _send_to_grc(grc_url, api_key, api_secret, payload)


def _build_telemetry_payload(
    normalized: dict,
    result: dict,
    client_id: str,
    risk_payload: dict,
) -> dict:
    """
    Construye el payload completo de telemetría para el GRC.
    Combina el evento normalizado + las métricas de riesgo de Fase 2.
    """
    # Extraer el external_event_id generado por el normalizador
    ext_id = normalized.get("external_event_id") or f"snl_{secrets.token_hex(8)}"

    payload = {
        # ── Campos del contrato base del GRC ──────────────────────────────
        "external_event_id": ext_id,
        "technical_id":      normalized.get("asset_id", "unknown"),
        "source":            f"Sentinel-ML [{normalized.get('source', 'unknown')}]",
        "event_type":        normalized.get("pattern_hint", result.get("pattern", "other")),
        "severity":          normalized.get("severity", _risk_to_severity(result.get("risk_level", "low"))),
        "description":       result.get("reason", normalized.get("description", "")),

        # ── Metadata del análisis de Sentinel ─────────────────────────────
        "sentinel_risk_level":  result.get("risk_level", "low"),
        "sentinel_pattern":     normalized.get("pattern_hint", "none"),
        "sentinel_action":      result.get("action", "monitor"),
        "sentinel_enriched":    result.get("enriched", False),
        "sentinel_version":     "2.0",

        # ── Datos de la fuente original ────────────────────────────────────
        "raw_data": {
            "source_siem":   normalized.get("source"),
            "src_ip":        normalized.get("src_ip"),
            "severity_score": normalized.get("severity_score"),
            "raw_hash":      normalized.get("raw_hash"),
            "timestamp":     normalized.get("timestamp"),
        },
    }

    # ── Métricas de riesgo financiero (Fase 2) — se añaden si el engine corrió
    if risk_payload:
        payload["risk_impact_update"] = risk_payload.get("risk_impact_update", {})
        payload["compliance_alert"]   = risk_payload.get("compliance_alert", {})
        payload["status"]             = risk_payload.get("status", "INCIDENT_REPORTED")
    else:
        # Sin risk engine — payload mínimo de compliance
        payload["status"] = "INCIDENT_REPORTED"

    return payload


async def _send_to_grc(
    grc_url: str,
    api_key: str,
    api_secret: str,
    payload: dict,
) -> bool:
    """
    Envía el payload al GRC forzando HTTPS y manejando redirecciones.
    """
    # Forzar HTTPS para evitar 301 y asegurar canal cifrado
    base_url = str(grc_url).replace("http://", "https://")
    endpoint = f"{base_url.rstrip('/')}/api/v1/integrations/telemetry"

    headers = {
        "X-API-Key":      api_key,
        "X-API-Secret":   api_secret,
        "Content-Type":   "application/json",
        "X-Forwarded-By": "Sentinel-ML/2.0",
    }

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as http:
            r = await http.post(endpoint, json=payload, headers=headers)
            
            if r.status_code in (200, 201, 202):
                logger.info(f"GRC notified OK — asset={payload.get('technical_id')} status={r.status_code}")
                return True
            
            if r.status_code == 409:
                logger.info(f"GRC: evento duplicado (409)")
                return True

            logger.warning(f"GRC Response Error: {r.status_code} — {r.text[:100]}")
            return False

    except Exception as e:
        logger.error(f"GRC Forward Exception: {e}")
        return False


def _risk_to_severity(risk_level: str) -> str:
    """Convierte el nivel de riesgo de Sentinel al formato de severidad del GRC."""
    return {"high": "critical", "medium": "high", "low": "low"}.get(risk_level, "medium")

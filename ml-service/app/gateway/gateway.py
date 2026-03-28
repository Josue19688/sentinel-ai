"""
Sentinel Gateway — Proxy Universal
El usuario solo configura URL + credenciales en su SIEM.
Sentinel hace todo lo demás de forma invisible.

Flujo:
  SIEM (cualquiera) → POST /analyze → enriquecimiento → correlación → GRC
"""
import time, logging, httpx, json
from fastapi import APIRouter, Request, HTTPException
from app.gateway.normalizer    import auto_normalize
from app.gateway.enricher      import enrich
from app.gateway.correlator    import correlate
from app.gateway.grc_forwarder import forward_to_grc
from app.gateway.store         import save_client_config, get_client_config
from app.db import get_db_conn

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["gateway"])


# ── Registro de cliente ───────────────────────────────────────────────────────
@router.post("/register")
async def register_client(request: Request):
    """
    El admin registra su GRC una sola vez.
    Recibe: grc_url, grc_api_key, grc_api_secret, company_name
    Devuelve: sentinel_api_key, sentinel_api_secret, webhook_url
    El script del SIEM apunta a webhook_url con las credenciales de Sentinel.
    """
    body = await request.json()
    required = ["grc_url", "grc_api_key", "grc_api_secret", "company_name"]
    for field in required:
        if field not in body:
            raise HTTPException(400, f"Campo requerido: {field}")

    import secrets, hashlib
    sentinel_key    = f"snl_{secrets.token_urlsafe(20)}"
    sentinel_secret = secrets.token_urlsafe(32)
    secret_salt     = secrets.token_hex(16)          # salt único por cliente
    secret_hash     = hashlib.sha256(
        (secret_salt + sentinel_secret).encode()
    ).hexdigest()

    async with get_db_conn() as conn:
        await conn.execute("""
            INSERT INTO sentinel_clients
                (sentinel_key, secret_hash, secret_salt, company_name, grc_url, grc_api_key, grc_api_secret)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (sentinel_key) DO NOTHING
        """, sentinel_key, secret_hash, secret_salt, body["company_name"],
             body["grc_url"], body["grc_api_key"], body["grc_api_secret"])

    return {
        "sentinel_api_key":    sentinel_key,
        "sentinel_api_secret": sentinel_secret,
        "webhook_url":         "/gateway/analyze",
        "message":             "Configuración guardada. Usa estas credenciales en tu script SIEM.",
        "script_hint":         "Reemplaza API_URL y credenciales en tu script existente."
    }


# ── Endpoint principal — recibe cualquier SIEM ────────────────────────────────
@router.post("/analyze")
async def analyze(request: Request):
    """
    Endpoint universal. El SIEM envía su alerta cruda aquí.
    Sentinel normaliza, enriquece, correlaciona y reenvía al GRC.
    El SIEM no sabe qué pasa adentro.
    """
    t0 = time.perf_counter()

    # 1. Autenticación simple — mismas cabeceras que tu GRC actual
    api_key    = request.headers.get("X-API-Key")
    api_secret = request.headers.get("X-API-Secret")

    if not api_key or not api_secret:
        raise HTTPException(401, "X-API-Key y X-API-Secret requeridos")

    client = await _verify_client(api_key, api_secret)
    if not client:
        raise HTTPException(403, "Credenciales inválidas")

    # 2. Recibir el JSON crudo — cualquier formato
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(400, "El body debe ser JSON válido")

    # 3. Normalización automática — detecta Wazuh, Sentinel, Syslog, etc.
    normalized = auto_normalize(raw)
    logger.info(f"[{client['company_name']}] Fuente detectada: {normalized['source']}")

    # 4. Enriquecimiento automático — threat intelligence, geolocalización
    enriched = await enrich(normalized)

    # 5. Correlación multi-fuente en ventana de 6 minutos
    correlation = await correlate(enriched, client["sentinel_key"])

    # 6. Construir resultado en lenguaje humano
    result = _build_result(enriched, correlation)

    # 7. Reenviar al GRC del cliente automáticamente
    grc_response = await forward_to_grc(client, result, raw)

    latency = (time.perf_counter() - t0) * 1000
    logger.info(f"[{client['company_name']}] Procesado en {latency:.1f}ms — nivel: {result['risk_level']}")

    return {
        "status":       "processed",
        "risk_level":   result["risk_level"],       # low | medium | high
        "pattern":      result["pattern"],           # nombre del ataque en español
        "action":       result["action"],            # ignore | review | escalate
        "reason":       result["reason"],            # explicación en lenguaje humano
        "enriched":     enriched["threat_intel"],    # True si IP estaba en listas negras
        "source_detected": normalized["source"],     # wazuh | sentinel | syslog | etc.
        "latency_ms":   round(latency, 1),
        "grc_notified": grc_response
    }


def _build_result(enriched: dict, correlation: dict) -> dict:
    """Traduce los datos técnicos a lenguaje de analista."""
    pattern  = correlation.get("pattern", "none")
    ti_match = enriched.get("threat_intel", False)
    score    = enriched.get("severity_score", 0.3)

    # Elevar automáticamente si IP está en listas negras
    if ti_match:
        score = max(score, 0.8)

    # Determinar nivel simple: low / medium / high
    if score >= 0.75 or pattern in ("lateral_movement", "brute_force_success", "c2_beacon"):
        risk_level = "high"
        action     = "escalate"
    elif score >= 0.45 or pattern in ("brute_force", "port_scan", "suspicious_outbound"):
        risk_level = "medium"
        action     = "review"
    else:
        risk_level = "low"
        action     = "ignore"

    # Razón en lenguaje humano
    reasons = {
        "lateral_movement":    "Autenticación fallida seguida de éxito desde misma IP hacia activo diferente en menos de 6 minutos.",
        "brute_force":         f"Múltiples intentos de autenticación fallidos ({correlation.get('count', '?')} intentos).",
        "brute_force_success": "Ataque de fuerza bruta exitoso — posibles credenciales comprometidas.",
        "port_scan":           "Alto volumen de conexiones denegadas a múltiples puertos desde misma IP.",
        "c2_beacon":           "Conexiones salientes regulares a IP en lista negra — posible beaconing C2.",
        "suspicious_outbound": "Tráfico saliente hacia destino inusual o en lista de amenazas.",
        "none":                "Evento procesado — sin patrón de ataque reconocido."
    }

    reason = reasons.get(pattern, reasons["none"])
    if ti_match:
        reason += " IP de origen encontrada en feeds de inteligencia de amenazas."

    return {
        "risk_level": risk_level,
        "pattern":    pattern,
        "action":     action,
        "reason":     reason
    }


async def _verify_client(api_key: str, api_secret: str) -> dict | None:
    import hashlib, hmac as hmac_lib
    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            SELECT sentinel_key, company_name, grc_url, grc_api_key, grc_api_secret,
                   secret_hash, secret_salt
            FROM sentinel_clients
            WHERE sentinel_key = $1 AND active = TRUE
        """, api_key)
    if not row:
        return None
    # Rehashear con el salt almacenado y comparar en tiempo constante
    expected_hash = hashlib.sha256(
        (row["secret_salt"] + api_secret).encode()
    ).hexdigest()
    if not hmac_lib.compare_digest(expected_hash, row["secret_hash"]):
        return None
    return dict(row)

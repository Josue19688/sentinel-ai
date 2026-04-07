"""
Sentinel Gateway — Proxy Universal
El usuario solo configura URL + credenciales en su SIEM.
Sentinel hace todo lo demás de forma invisible.

Flujo actualizado (3 capas):
  SIEM → POST /analyze
       → normalización + enriquecimiento + correlación
       → [Capa 1] KafkaFilter (filtra ruido)
       → [Capa 2] River ML (detección streaming, vía ingest_queue)
       → [Capa 3] IsolationForest (asíncrono, vía escalate_queue)
       → GRC

Cambios respecto a la versión anterior:
  1. Sección 4.1: reemplazado lpush manual por get_filter().send()
     → activa la Capa 1 en cada evento que entra
  2. Sección 5.5: eliminada la llamada directa a run_inference()
     → el IF ahora es asíncrono, no bloquea el endpoint
     → River ML decide si escalar vía escalate_queue
"""

import time
import logging
import json
import uuid
from fastapi import APIRouter, Depends, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

from typing import Annotated
from app.auth.dependencies import CurrentApiClient, CurrentUser, get_current_identity, require_role
from app.normalizer.universal  import normalize as auto_normalize
from app.detection.kafka_filter import get_filter
from app.gateway.enricher                  import enrich
from app.gateway.correlator                import correlate
from app.worker                            import celery
from app.db                                import get_redis
from app.calculator.quick_risk             import calculate as calculate_risk
from app.repositories.gateway             import create_sentinel_client
from app.repositories.asset               import find_asset_by_event
from app.config import settings
from app.security.sanitizer               import sanitize

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["gateway"])


# ── Registro de cliente ───────────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register_client(
    request: Request,
    _admin: CurrentUser = Depends(require_role("admin")),
):
    """
    El admin registra su GRC una sola vez.
    Recibe: grc_url, grc_api_key, grc_api_secret, company_name
    Devuelve: sentinel_api_key, sentinel_api_secret, webhook_url
    """
    body = await request.json()
    required = ["grc_url", "grc_api_key", "grc_api_secret", "company_name"]
    for field in required:
        if field not in body:
            raise HTTPException(400, f"Campo requerido: {field}")

    import secrets
    import hashlib
    sentinel_key    = f"snl_{secrets.token_urlsafe(20)}"
    sentinel_secret = secrets.token_urlsafe(32)
    secret_salt     = secrets.token_hex(16)
    secret_hash     = hashlib.sha256(
        (secret_salt + sentinel_secret).encode()
    ).hexdigest()

    await create_sentinel_client(
        sentinel_key  = sentinel_key,
        secret_hash   = secret_hash,
        secret_salt   = secret_salt,
        company_name  = body["company_name"],
        grc_url       = body["grc_url"],
        grc_api_key   = body["grc_api_key"],
        grc_api_secret= body["grc_api_secret"],
    )

    return {
        "sentinel_api_key":    sentinel_key,
        "sentinel_api_secret": sentinel_secret,
        "webhook_url":         "/gateway/analyze",
        "message":             "Configuración guardada. Usa estas credenciales en tu script SIEM.",
        "script_hint":         "Reemplaza API_URL y credenciales en tu script existente."
    }


# ── Sandbox Forense — Endpoint Público ───────────────────────────────────────

# ── Sandbox Forense ──────────────────────────────────────────────────────────

MAX_FILE_SIZE       = 10 * 1024 * 1024
ALLOWED_MAGIC_BYTES = (b'{', b'[')
_SANDBOX_RATE_LIMIT = 10   # uploads por hora por IP


async def _check_sandbox_rate_limit(client_ip: str) -> None:
    """Bloquea si el mismo IP supera 10 uploads por hora."""
    redis = await get_redis()
    key   = f"sandbox_rl:{client_ip}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 3600)   # ventana de 1 hora
    if count > _SANDBOX_RATE_LIMIT:
        raise HTTPException(
            429,
            f"Limite de {_SANDBOX_RATE_LIMIT} archivos/hora alcanzado. Intenta mas tarde."
        )


@router.post("/sandbox", status_code=202)
async def process_sandbox_upload(
    request: Request,
    file: UploadFile = File(...),
    allow_telemetry_training: bool = Form(False),
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """
    Ingesta blindada para el Sandbox Público.
    Valida Magic Bytes, tamaño y opt-in GDPR antes de encolar.
    """
    client_ip = request.client.host if request.client else "unknown"
    await _check_sandbox_rate_limit(client_ip)

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "El archivo excede el límite estricto de 10MB.")

    if content.lstrip()[:1] not in ALLOWED_MAGIC_BYTES:
        raise HTTPException(
            415,
            "El archivo no es JSON o JSONL válido (Magic Bytes Mismatch). "
            "Se prohíben ejecutables."
        )

    session_uuid = str(uuid.uuid4())
    celery.send_task(
        name="process_sandbox_file",
        args=[session_uuid, content.decode("utf-8", errors="ignore"), allow_telemetry_training],
    )

    return JSONResponse(
        status_code=202,
        content={
            "status":                 "processing",
            "message":                "Archivo validado y encolado para escrutinio IA.",
            "session_id":             session_uuid,
            "legal_telemetry_granted": allow_telemetry_training,
            "disclaimer":             "Tu reporte se purgará físicamente en 24 horas por privacidad.",
        },
    )


@router.get("/sandbox/{session_id}")
async def get_sandbox_report(session_id: str):
    """Retorna el reporte forense o 410 Gone si expiró (24h GDPR)."""
    redis_client = await get_redis()
    data = await redis_client.get(f"sandbox:{session_id}")

    if not data:
        return JSONResponse(
            status_code=410,
            content={
                "message": (
                    "Por políticas de privacidad (GDPR), tu reporte de 24 horas "
                    "fue destruido irrevocablemente. Sube nuevamente el archivo."
                )
            },
        )

    parsed = json.loads(data)
    if "error" in parsed:
        return JSONResponse(status_code=400, content=parsed)

    return parsed


# ── Endpoint principal — recibe cualquier SIEM ────────────────────────────────

from pydantic import BaseModel

class AnalyzePayload(BaseModel):
    id: str | int
    model_config = {"extra": "forbid"}

@router.post("/analyze")
async def analyze(
    payload: AnalyzePayload,
    request: Request,
    identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)] = None,
):
    """
    Endpoint universal. El SIEM envía su alerta cruda aquí.
    Sentinel normaliza, enriquece, correlaciona y reenvía al GRC.
    La inferencia ML ocurre de forma asíncrona — no bloquea la respuesta.
    """
    t0 = time.perf_counter()

    # La autenticación ahora es manejada por app.auth.dependencies.
    # API Key gestionada por el Dashboard (sentinel-grc UI).
    # Extraer ID y nombre de forma robusta (soporta CurrentUser y CurrentApiClient)
    if hasattr(identity, "email"): # CurrentUser
        client_id    = identity.id
        client_name  = identity.email
        sentinel_key = "session"
    else: # CurrentApiClient
        client_id    = getattr(identity, "user_id", "unknown")
        client_name  = getattr(identity, "name", "unknown")
        sentinel_key = getattr(identity, "key_id", "unknown")


    
    # 2. Recibir JSON crudo y sanitizar contra XSS/SQLi preventivo
    try:
        raw = payload.model_dump(exclude_unset=True)
        raw = sanitize(raw)
    except Exception:
        raise HTTPException(400, "El body debe ser JSON válido o falló la sanitización.")

    # 3. Normalización agnóstica — sentinel_v2
    normalized = auto_normalize(raw)
    logger.info(f"[{client_name}] Fuente: {normalized['source']}")

    # 4. Enriquecimiento — threat intel + geolocalización
    enriched = await enrich(normalized)
    enriched["sentinel_key"] = sentinel_key
    enriched["client_id"]    = client_id

    # 5. Correlación multi-fuente (ventana 6 minutos) para obtener DELTA
    correlation = await correlate(enriched, sentinel_key)

    # 6. Buscar activo real en Sentinel ML para obtener ASSET VALUE
    asset_data = await find_asset_by_event(
        client_id    = client_id,
        hostname     = enriched.get("hostname") or enriched.get("asset_id"),
        ip_address   = enriched.get("ip_address") or enriched.get("dst_ip"),
        technical_id = enriched.get("technical_id"),
    )

    # 7. Sincronizar features_vector con datos reales ANTES de enviar a la IA
    if "features_vector" in enriched:
        enriched["features_vector"]["timestamp_delta"] = correlation.get("delta", 300.0)

        if asset_data:
            # ── asset_value: score normalizado desde CIA + valor financiero ──
            # CIA (C/I/A 1-5) normalizado a 0-1
            cia_score = (
                asset_data.get("valor_confidencialidad", 3) +
                asset_data.get("valor_integridad",       3) +
                asset_data.get("valor_disponibilidad",   3)
            ) / 15.0

            # Valor financiero normalizado contra el techo configurado
            valor_activo = float(asset_data.get("valor_activo") or 0.0)
            ceiling      = float(getattr(settings, "ASSET_VALUE_CEILING", 100_000) or 100_000)
            valor_norm   = min(valor_activo / ceiling, 1.0) if ceiling > 0 else 0.0

            # asset_value para el IF: combina importancia CIA + valor financiero
            enriched["features_vector"]["asset_value"] = round(
                (cia_score * 0.6) + (valor_norm * 0.4), 4
            )

            # ── asset_meta: snapshot completo para risk_engine en escalate ──
            # Viaja dentro del evento a través de ingest_queue → escalate_queue
            # para que risk_engine tenga datos reales sin volver a la DB.
            enriched["asset_meta"] = {
                "valor_activo":             valor_activo,
                "valor_confidencialidad":   asset_data.get("valor_confidencialidad", 3),
                "valor_integridad":         asset_data.get("valor_integridad",       3),
                "valor_disponibilidad":     asset_data.get("valor_disponibilidad",   3),
                "clasificacion_criticidad": asset_data.get("clasificacion_criticidad"),
                "contiene_pii":             bool(asset_data.get("contiene_pii", False)),
                "contiene_pci":             bool(asset_data.get("contiene_pci", False)),
                "contiene_phi":             bool(asset_data.get("contiene_phi", False)),
                "contiene_pfi":             bool(asset_data.get("contiene_pfi", False)),
            }
        else:
            # Activo no registrado en Sentinel — risk_engine usará fallback
            enriched["asset_meta"] = None

    # ── Capa 1 activa ───────────────────────────────────────────
    # Ahora sí enviamos el evento con toda la telemetría real inyectada
    try:
        sent = await get_filter().send(enriched, from_siem=True)
        if sent:
            celery.send_task("process_ingest_queue")
            logger.info(f"[{client_name}] Alerta enviada con delta={correlation.get('delta')}")
        else:
            logger.debug(f"[{client_name}] Alerta descartada (ruido puro)")
    except Exception as e:
        logger.error(f"Error en KafkaFilter/ingest: {e}")

    # 8. Resultado para el Dashboard
    result       = _build_result(enriched, correlation, normalized)
    calculate_risk(enriched, asset_data=asset_data)

    # 8. Reenvío al GRC — DESHABILITADO (Sentinel ahora es independiente)

    latency = (time.perf_counter() - t0) * 1000
    logger.info(f"[{client_name}] {latency:.1f}ms — {result['risk_level']}")

    latency = (time.perf_counter() - t0) * 1000
    logger.info(f"[{client_name}] {latency:.1f}ms — {result['risk_level']} (Ingested)")

    return {
        "status":         "processed",
        "transaction_id": enriched.get("transaction_id", "unknown"),
        "received_at":    time.time(),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_result(enriched: dict, correlation: dict, normalized: dict = None) -> dict:
    """Traduce datos técnicos a lenguaje de analista."""
    # Prioridad 1: Correlación compleja (el viejo)
    pattern  = correlation.get("pattern", "none")
    
    # Prioridad 2: IA del Normalizador V2 (si el viejo no detectó nada)
    if pattern == "none" and normalized:
        v2_pattern = normalized.get("pattern_hint", "none")
        if v2_pattern != "none":
            pattern = v2_pattern

    ti_match = enriched.get("threat_intel", False)
    score    = enriched.get("severity_score", 0.3)

    if ti_match:
        score = max(score, 0.8)

    if score >= 0.75 or pattern in ("lateral_movement", "brute_force_success", "c2_beacon"):
        risk_level, action = "high",   "escalate"
    elif score >= 0.45 or pattern in ("brute_force", "port_scan", "suspicious_outbound"):
        risk_level, action = "medium", "review"
    else:
        risk_level, action = "low",    "ignore"

    reasons = {
        "lateral_movement":    "Autenticación fallida seguida de éxito desde misma IP en menos de 6 minutos.",
        "brute_force":         f"Múltiples intentos fallidos ({correlation.get('count', '?')} intentos).",
        "brute_force_success": "Ataque de fuerza bruta exitoso — credenciales posiblemente comprometidas.",
        "port_scan":           "Alto volumen de conexiones denegadas a múltiples puertos desde misma IP.",
        "c2_beacon":           "Conexiones salientes regulares a IP en lista negra — posible C2.",
        "suspicious_outbound": "Tráfico saliente hacia destino inusual o en lista de amenazas.",
        "none":                "Evento procesado — sin patrón de ataque reconocido.",
    }

    reason = reasons.get(pattern, reasons["none"])
    
    # Fallback para la descripción detallada de la IA
    if reason == reasons["none"] and normalized:
        reason = normalized.get("description", reasons["none"])

    if ti_match:
        reason += " IP encontrada en feeds de inteligencia de amenazas."

    return {"risk_level": risk_level, "pattern": pattern, "action": action, "reason": reason}


# _verify_client() eliminada — la autenticación es manejada por
# app.auth.dependencies.get_current_api_client (API Key + bcrypt).

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

import time, logging, httpx, json, uuid
from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse

from app.sentinel_v2.normalizer.universal  import normalize as auto_normalize
from app.sentinel_v2.streaming.kafka_filter import get_filter
from app.gateway.enricher                  import enrich
from app.gateway.correlator                import correlate
from app.gateway.grc_forwarder             import forward_to_grc
from app.worker                            import celery
from app.gateway.store                     import save_client_config, get_client_config
from app.db                                import get_db_conn, get_redis
from app.sentinel_v2.calculator.risk       import calculate as calculate_risk

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/gateway", tags=["gateway"])


# ── Registro de cliente ───────────────────────────────────────────────────────

@router.post("/register")
async def register_client(request: Request):
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

    import secrets, hashlib
    sentinel_key    = f"snl_{secrets.token_urlsafe(20)}"
    sentinel_secret = secrets.token_urlsafe(32)
    secret_salt     = secrets.token_hex(16)
    secret_hash     = hashlib.sha256(
        (secret_salt + sentinel_secret).encode()
    ).hexdigest()

    async with get_db_conn() as conn:
        await conn.execute("""
            INSERT INTO sentinel_clients
                (sentinel_key, secret_hash, secret_salt, company_name,
                 grc_url, grc_api_key, grc_api_secret)
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


# ── Sandbox Forense — Endpoint Público ───────────────────────────────────────

MAX_FILE_SIZE      = 10 * 1024 * 1024
ALLOWED_MAGIC_BYTES = (b'{', b'[')


@router.post("/sandbox")
async def process_sandbox_upload(
    file: UploadFile = File(...),
    allow_telemetry_training: bool = Form(False),
):
    """
    Ingesta blindada para el Sandbox Público.
    Valida Magic Bytes, tamaño y opt-in GDPR antes de encolar.
    """
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

@router.post("/analyze")
async def analyze(request: Request):
    """
    Endpoint universal. El SIEM envía su alerta cruda aquí.
    Sentinel normaliza, enriquece, correlaciona y reenvía al GRC.
    La inferencia ML ocurre de forma asíncrona — no bloquea la respuesta.
    """
    t0 = time.perf_counter()

    # 1. Autenticación HMAC
    api_key    = request.headers.get("X-API-Key")
    api_secret = request.headers.get("X-API-Secret")

    if not api_key or not api_secret:
        raise HTTPException(401, "X-API-Key y X-API-Secret requeridos")

    client = await _verify_client(api_key, api_secret)
    if not client:
        raise HTTPException(403, "Credenciales inválidas")

    # 2. Recibir JSON crudo
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(400, "El body debe ser JSON válido")

    # 3. Normalización agnóstica — sentinel_v2
    normalized = auto_normalize(raw)
    logger.info(f"[{client['company_name']}] Fuente: {normalized['source']}")

    # 4. Enriquecimiento — threat intel + geolocalización
    enriched = await enrich(normalized)
    enriched["sentinel_key"] = client["sentinel_key"]

    # ── CAMBIO 1: Capa 1 activa ───────────────────────────────────────────
    # Antes: lpush manual a Redis (saltaba el filtro)
    # Ahora: get_filter().send() aplica KafkaFilter antes de encolar
    # Si el evento no supera el filtro, se descarta silenciosamente aquí.
    # River ML (Capa 2) procesará el evento vía process_ingest_queue.
    # Si River lo marca como sospechoso, irá a escalate_queue → IF (Capa 3).
    try:
        sent = get_filter().send(enriched)
        if sent:
            celery.send_task("process_ingest_queue")
            logger.debug(f"[{client['company_name']}] Evento encolado vía KafkaFilter")
        else:
            logger.debug(f"[{client['company_name']}] Evento descartado por KafkaFilter")
    except Exception as e:
        logger.error(f"Error en KafkaFilter/ingest: {e}")
    # ── FIN CAMBIO 1 ──────────────────────────────────────────────────────

    # 5. Correlación multi-fuente (ventana 6 minutos) — sin cambios
    correlation = await correlate(enriched, client["sentinel_key"])

    # ── CAMBIO 2: eliminada inferencia síncrona ───────────────────────────
    # Antes: run_inference() bloqueaba el endpoint añadiendo 50ms+
    # Ahora: River ML (Capa 2) decide si escalar al IF de forma asíncrona.
    #        El endpoint responde inmediatamente. El IF corre en background.
    #        Resultado: latencia del endpoint reducida ~50ms en promedio.
    # ── FIN CAMBIO 2 ──────────────────────────────────────────────────────

    # 6. Resultado para el GRC — sin cambios
    result       = _build_result(enriched, correlation)
    risk_metrics = calculate_risk(enriched)

    # 7. Reenvío al GRC con anti-saturación — sin cambios
    redis_client = await get_redis()
    if result["risk_level"] in ["high", "medium"]:
        lock_key     = f"grc_lock:{api_key}:{enriched['asset_id']}:{result['pattern']}"
        already_sent = await redis_client.get(lock_key)

        if not already_sent:
            await redis_client.setex(lock_key, 60, "sent")
            grc_response = await forward_to_grc(client, result, enriched)
            logger.info(f"[{client['company_name']}] GRC: alerta enviada")
        else:
            grc_response = {
                "status":  "suppressed",
                "message": "Alert suppressed by rate-limiter (Deduplication).",
            }
    else:
        grc_response = {
            "status":  "filtered",
            "message": f"Low risk alert ({result['risk_level']}) filtered locally.",
        }

    latency = (time.perf_counter() - t0) * 1000
    logger.info(f"[{client['company_name']}] {latency:.1f}ms — {result['risk_level']}")

    return {
        "status":          "processed",
        "risk_level":      result["risk_level"],
        "pattern":         result["pattern"],
        "action":          result["action"],
        "sle_usd":         risk_metrics.sle_usd,
        "ale_usd":         risk_metrics.ale_usd,
        "iso_control":     risk_metrics.iso_control,
        "reason":          result["reason"],
        "enriched":        enriched["threat_intel"],
        "source_detected": normalized["source"],
        "latency_ms":      round(latency, 1),
        "grc_notified":    grc_response,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_result(enriched: dict, correlation: dict) -> dict:
    """Traduce datos técnicos a lenguaje de analista."""
    pattern  = correlation.get("pattern", "none")
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
    if ti_match:
        reason += " IP encontrada en feeds de inteligencia de amenazas."

    return {"risk_level": risk_level, "pattern": pattern, "action": action, "reason": reason}


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
    expected = hashlib.sha256((row["secret_salt"] + api_secret).encode()).hexdigest()
    if not hmac_lib.compare_digest(expected, row["secret_hash"]):
        return None
    return dict(row)

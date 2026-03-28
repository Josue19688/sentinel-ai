"""
Validación HMAC-SHA256 por request.
Previene: replay attacks, manipulación de payload, acceso no autorizado.

Header requerido:
    X-Client-ID: <client_id>
    X-GRC-Signature: <hmac_sha256(payload + timestamp + client_id, client_secret)>
    X-Timestamp: <unix_timestamp>  (rechaza si > 30s de diferencia)

Modos:
    LIVE   → HMAC estricto obligatorio para todos los clientes
    SHADOW → HMAC verificado si hay firma; advertencia si no hay
    DUMMY  → Bypass permitido para desarrollo local
"""
import hmac, hashlib, time, logging
from fastapi import Request, HTTPException
from app.db import get_db_conn
from app.config import settings

logger = logging.getLogger(__name__)
TIMESTAMP_TOLERANCE_S = 30


async def verify_hmac(request: Request) -> str:
    client_id = request.headers.get("X-Client-ID")

    # Sin client_id: solo permitido en DUMMY
    if not client_id:
        if settings.MODEL_MODE == "DUMMY":
            logger.warning("Dev mode: anonymous request accepted (MODEL_MODE=DUMMY)")
            return "anonymous"
        raise HTTPException(401, "Header X-Client-ID requerido")

    signature = request.headers.get("X-GRC-Signature")
    timestamp  = request.headers.get("X-Timestamp")

    # Sin firma completa: solo permitido en DUMMY
    if not all([signature, timestamp]):
        if settings.MODEL_MODE == "DUMMY":
            logger.warning(f"Dev mode: skipping HMAC for client {client_id} (MODEL_MODE=DUMMY)")
            return client_id
        raise HTTPException(401, "Headers X-GRC-Signature y X-Timestamp requeridos")

    # Anti-replay: ventana de 30 segundos
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(401, "X-Timestamp debe ser un entero Unix")

    if abs(time.time() - ts) > TIMESTAMP_TOLERANCE_S:
        raise HTTPException(401, "Request expirado (anti-replay: ventana 30s)")

    # Obtener secret del cliente desde DB
    secret = await _get_client_secret(client_id)
    if not secret:
        raise HTTPException(403, f"Cliente desconocido o inactivo: {client_id}")

    # Reconstruir y verificar firma HMAC-SHA256
    body = await request.body()
    expected = hmac.new(
        secret.encode(),
        f"{body.decode()}{timestamp}{client_id}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        logger.warning(f"HMAC mismatch para cliente {client_id}")
        if settings.MODEL_MODE == "LIVE":
            raise HTTPException(403, "Firma inválida")
        # En SHADOW: registrar el fallo pero no bloquear
        logger.warning(f"Shadow mode: permitiendo a pesar de HMAC mismatch para {client_id}")

    return client_id


async def _get_client_secret(client_id: str) -> str | None:
    """
    Lee el client_secret desde DB.
    En producción con alto volumen: cachear en Redis con TTL=60s.
    """
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT client_secret FROM ml_clients WHERE client_id=$1 AND active=TRUE",
            client_id
        )
        return row["client_secret"] if row else None

"""
Hash Chain — Cadena inmutable de auditoría (ISO 27001 A.12.4.2)
Cada registro firma al anterior con SHA-256.
Verificable completamente por SQL sin herramientas externas.

CONCURRENCIA:
    log_audit_event() usa una transacción con SELECT FOR UPDATE para garantizar
    que el previous_hash sea siempre el del último registro real, incluso bajo
    carga concurrente. Sin este lock, dos requests simultáneos podrían leer el
    mismo previous_hash y bifurcar la cadena, invalidando verify_chain().
"""
import hashlib
import json
import logging
from app.db import get_db_conn

logger = logging.getLogger(__name__)


async def log_audit_event(event_type: str, entity_id, actor: str, payload: dict):
    """
    Registra un evento en el AuditLog con hash encadenado.
    La transacción + FOR UPDATE garantiza la secuencialidad incluso bajo carga concurrente.
    """
    async with get_db_conn() as conn:
        async with conn.transaction():
            # FOR UPDATE serializa inserciones concurrentes — previene bifurcación de la cadena
            last = await conn.fetchrow(
                "SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE"
            )
            previous_hash = last["current_hash"] if last else "GENESIS"

            # Calcular hash del registro actual
            content = json.dumps({
                "event_type":    event_type,
                "entity_id":     str(entity_id),
                "actor":         actor,
                "payload":       payload,
                "previous_hash": previous_hash
            }, sort_keys=True)
            current_hash = hashlib.sha256(content.encode()).hexdigest()

            await conn.execute("""
                INSERT INTO audit_log
                    (event_type, entity_id, actor, payload, previous_hash, current_hash)
                VALUES ($1, $2, $3, $4, $5, $6)
            """,
                event_type, str(entity_id), actor,
                json.dumps(payload), previous_hash, current_hash
            )


async def verify_chain() -> dict:
    """
    Verifica la integridad completa del Hash Chain.
    Si alguien modificó un registro manualmente, la cadena se rompe aquí.
    """
    async with get_db_conn() as conn:
        records = await conn.fetch(
            "SELECT * FROM audit_log ORDER BY id ASC"
        )

    if not records:
        return {"status": "empty", "verified": True, "records": 0}

    broken_at = None
    prev_hash  = "GENESIS"

    for rec in records:
        content = json.dumps({
            "event_type":    rec["event_type"],
            "entity_id":     rec["entity_id"],
            "actor":         rec["actor"],
            "payload":       json.loads(rec["payload"]) if rec["payload"] else {},
            "previous_hash": prev_hash
        }, sort_keys=True)
        expected = hashlib.sha256(content.encode()).hexdigest()

        if expected != rec["current_hash"]:
            broken_at = rec["id"]
            logger.error(f"Hash chain BROKEN at record {rec['id']}")
            break

        prev_hash = rec["current_hash"]

    if broken_at:
        return {
            "status":            "COMPROMISED",
            "verified":          False,
            "broken_at_record":  broken_at,
            "message":           "La cadena de auditoría ha sido comprometida. Iniciar investigación forense."
        }

    return {
        "status":            "INTACT",
        "verified":          True,
        "records_verified":  len(records),
        "latest_hash":       prev_hash[:16] + "..."
    }

"""
PSI Monitor — Population Stability Index
Detecta drift en los datos de entrada.
Si el formato de logs del SIEM cambia, el PSI sube y el Circuit Breaker se abre.

Circuit Breaker — máquina de estados completa:
    CLOSED    → sistema operando normalmente
    OPEN      → ML Service deshabilitado, fallback a ISO 27005
                Auto-transición a HALF_OPEN después de CB_RECOVERY_TIMEOUT_S segundos
    HALF_OPEN → probando recuperación con una inferencia de prueba
                → CLOSED si la inferencia tiene éxito (close_circuit)
                → OPEN   si la inferencia falla (record_failure)
"""
import numpy as np, logging
from dataclasses import dataclass
from datetime import datetime, timezone
from app.db import get_db_conn
from app.config import settings

logger = logging.getLogger(__name__)
PSI_THRESHOLD = 0.2   # > 0.2 indica drift significativo


@dataclass
class CircuitBreakerState:
    state:    str
    failures: int


async def check_circuit_breaker() -> CircuitBreakerState:
    """
    Lee el estado del Circuit Breaker y aplica la auto-transición
    OPEN → HALF_OPEN cuando vence el timeout de recuperación.
    """
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT state, failures, opened_at FROM ml_circuit_breaker LIMIT 1"
        )

    if not row:
        return CircuitBreakerState(state="CLOSED", failures=0)

    state = row["state"]

    # Auto-transición OPEN → HALF_OPEN cuando vence CB_RECOVERY_TIMEOUT_S
    if state == "OPEN" and row["opened_at"]:
        now     = datetime.now(timezone.utc)
        elapsed = (now - row["opened_at"]).total_seconds()

        if elapsed >= settings.CB_RECOVERY_TIMEOUT_S:
            async with get_db_conn() as conn:
                await conn.execute(
                    "UPDATE ml_circuit_breaker SET state='HALF_OPEN', updated_at=NOW()"
                )
            logger.info(
                f"Circuit Breaker OPEN → HALF_OPEN "
                f"(elapsed: {elapsed:.0f}s / timeout: {settings.CB_RECOVERY_TIMEOUT_S}s)"
            )
            state = "HALF_OPEN"

    return CircuitBreakerState(state=state, failures=row["failures"])


async def open_circuit(reason: str):
    logger.warning(f"Circuit Breaker → OPEN: {reason}")
    async with get_db_conn() as conn:
        await conn.execute("""
            UPDATE ml_circuit_breaker
            SET state='OPEN', opened_at=NOW(), updated_at=NOW()
        """)


async def close_circuit():
    """
    Cierra el Circuit Breaker después de una inferencia exitosa en estado HALF_OPEN.
    Reinicia el contador de fallos para empezar con pizarra limpia.
    """
    logger.info("Circuit Breaker → CLOSED (sistema recuperado)")
    async with get_db_conn() as conn:
        await conn.execute("""
            UPDATE ml_circuit_breaker
            SET state='CLOSED', failures=0, opened_at=NULL, updated_at=NOW()
        """)


async def record_failure():
    async with get_db_conn() as conn:
        row = await conn.fetchrow("""
            UPDATE ml_circuit_breaker
            SET failures = failures + 1, last_fail = NOW(), updated_at = NOW()
            RETURNING failures
        """)
        if row and row["failures"] >= settings.CB_FAILURE_THRESHOLD:
            await open_circuit(f"Failure threshold reached ({row['failures']})")


async def compute_psi() -> float:
    """
    Calcula PSI comparando distribución de severity_score
    entre la última semana y las 3 semanas anteriores.
    """
    async with get_db_conn() as conn:
        recent = await conn.fetch("""
            SELECT severity_score FROM normalized_features
            WHERE created_at > NOW() - INTERVAL '7 days'
            LIMIT 5000
        """)
        baseline = await conn.fetch("""
            SELECT severity_score FROM normalized_features
            WHERE created_at BETWEEN NOW() - INTERVAL '28 days'
                              AND NOW() - INTERVAL '7 days'
            LIMIT 5000
        """)

    if len(recent) < 100 or len(baseline) < 100:
        return 0.0  # datos insuficientes

    r = np.array([r["severity_score"] for r in recent])
    b = np.array([r["severity_score"] for r in baseline])

    bins  = np.linspace(0, 1, 11)
    r_hist, _ = np.histogram(r, bins=bins)
    b_hist, _ = np.histogram(b, bins=bins)

    r_pct = (r_hist + 1) / (len(r) + len(bins))
    b_pct = (b_hist + 1) / (len(b) + len(bins))

    psi = float(np.sum((r_pct - b_pct) * np.log(r_pct / b_pct)))

    if psi > PSI_THRESHOLD:
        logger.warning(f"PSI={psi:.3f} > threshold {PSI_THRESHOLD} — drift detected")
        await open_circuit(f"PSI drift: {psi:.3f}")

    return psi

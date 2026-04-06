"""
Correlator — Motor de Correlación Multi-Fuente
Detecta los 5 patrones del Módulo 4 automáticamente.
El usuario no configura nada — los patrones se aplican siempre.

Ventana de correlación: 6 minutos por activo + IP.
Persistencia: Redis (TTL 6 minutos por clave).

Patrones detectados:
1. Movimiento lateral     — auth fallida → éxito en activo diferente
2. Fuerza bruta           — N fallos en ventana de tiempo
3. Fuerza bruta exitosa   — fallos seguidos de éxito misma IP
4. Escaneo de puertos     — alto volumen conexiones denegadas multi-puerto
5. Beaconing C2           — IP en listas negras con conexiones regulares
6. Tráfico saliente susp. — destino inusual o en threat intel

FIX: Usa un pool de conexiones compartido en lugar de abrir/cerrar
     una conexión nueva por cada evento. Esto elimina la latencia de
     ~15s causada por timeouts de DNS al conectar a ml-redis.
"""
import json, logging, time
import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger(__name__)

BRUTE_FORCE_THRESHOLD  = 5   # intentos fallidos en 6 min
PORT_SCAN_THRESHOLD    = 10  # puertos distintos en 6 min
WINDOW_SECONDS         = 360 # 6 minutos

# ── Pool compartido — se inicializa una sola vez ──────────────────────────────
# socket_connect_timeout: falla rápido si Redis no está disponible (1s)
# socket_timeout: falla rápido en operaciones (1s)
_redis_pool: aioredis.Redis | None = None


def get_redis_client() -> aioredis.Redis:
    """Devuelve el cliente Redis compartido con pool de conexiones."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=1,   # ← falla en 1s si no hay Redis
            socket_timeout=1,           # ← operaciones fallan en 1s
            max_connections=20,
        )
    return _redis_pool


async def correlate(enriched: dict, client_key: str) -> dict:
    src_ip   = enriched.get("src_ip")
    asset_id = enriched.get("asset_id", "unknown")
    ev_type  = enriched.get("event_type", "").lower()
    score    = enriched.get("severity_score", 0.3)
    ti_match = enriched.get("threat_intel", False)

    await _store_event(client_key, src_ip, asset_id, ev_type, score, enriched)

    history = await _get_history(client_key, src_ip)

    delta = 300.0
    if len(history) > 1:
        prev_ts = history[-2].get("ts", time.time())
        delta   = max(0.1, time.time() - prev_ts)

    pattern, count = _detect_pattern(history, enriched, ti_match)

    return {
        "pattern":       pattern,
        "count":         count,
        "window_events": len(history),
        "delta":         round(delta, 2),
    }


def _detect_pattern(history: list, current: dict, ti_match: bool) -> tuple:
    """Aplica los 5 patrones del Módulo 4."""
    ev_type  = current.get("event_type", "").lower()
    asset_id = current.get("asset_id", "")

    # 1. Beaconing C2 — IP maliciosa conocida
    if ti_match:
        return "c2_beacon", 1

    # 2. Movimiento lateral — fallo en activo A, éxito en activo B, misma IP
    failed_assets  = {e["asset_id"] for e in history if _is_auth_failure(e)}
    success_assets = {e["asset_id"] for e in history if _is_auth_success(e)}
    if failed_assets and success_assets and not failed_assets.issubset(success_assets):
        return "lateral_movement", len(failed_assets) + len(success_assets)

    # 3. Fuerza bruta exitosa — fallos + éxito en mismo activo
    asset_history = [e for e in history if e.get("asset_id") == asset_id]
    failures  = [e for e in asset_history if _is_auth_failure(e)]
    successes = [e for e in asset_history if _is_auth_success(e)]
    if len(failures) >= 3 and successes:
        return "brute_force_success", len(failures)

    # 4. Fuerza bruta — muchos fallos
    if len(failures) >= BRUTE_FORCE_THRESHOLD:
        return "brute_force", len(failures)

    # 5. Escaneo de puertos — muchos puertos distintos bloqueados
    blocked = [e for e in history if "block" in e.get("event_type", "").lower()
               or "deny"     in e.get("event_type", "").lower()
               or "firewall" in e.get("event_type", "").lower()]
    if len(blocked) >= PORT_SCAN_THRESHOLD:
        return "port_scan", len(blocked)

    # 6. Tráfico saliente sospechoso
    if "outbound" in ev_type or "egress" in ev_type:
        return "suspicious_outbound", 1

    return "none", len(history)


def _is_auth_failure(event: dict) -> bool:
    ev = event.get("event_type", "").lower()
    return any(k in ev for k in ["failed", "failure", "invalid", "denied",
                                  "authentication_failed", "brute"])

def _is_auth_success(event: dict) -> bool:
    ev = event.get("event_type", "").lower()
    return any(k in ev for k in ["success", "accepted", "authenticated",
                                  "logged_in", "login"])


async def _store_event(client_key: str, src_ip: str, asset_id: str,
                       ev_type: str, score: float, enriched: dict):
    """Guarda el evento en Redis con TTL de 6 minutos."""
    if not src_ip:
        return
    try:
        r = get_redis_client()
        key   = f"corr:{client_key}:{src_ip}"
        entry = json.dumps({
            "asset_id":   asset_id,
            "event_type": ev_type,
            "score":      score,
            "ts":         time.time()
        })
        await r.rpush(key, entry)
        await r.expire(key, WINDOW_SECONDS)
    except Exception as e:
        logger.warning(f"Correlator store failed: {e}")


async def _get_history(client_key: str, src_ip: str) -> list:
    """Lee el historial de eventos de la ventana actual."""
    if not src_ip:
        return []
    try:
        r = get_redis_client()
        key        = f"corr:{client_key}:{src_ip}"
        raw_events = await r.lrange(key, 0, -1)
        now        = time.time()
        events     = []
        for e in raw_events:
            try:
                ev = json.loads(e)
                if now - ev.get("ts", 0) <= WINDOW_SECONDS:
                    events.append(ev)
            except Exception:
                pass
        return events
    except Exception as e:
        logger.warning(f"Correlator read failed: {e}")
        return []
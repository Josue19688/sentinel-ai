"""
Conexión a PostgreSQL — pool asyncpg compartido y sensible al loop.
"""
import asyncio
import asyncpg
import redis.asyncio as redis
from contextlib import asynccontextmanager
from app.config import settings

_pool = None
_redis = None

async def get_pool():
    global _pool
    current_loop = asyncio.get_running_loop()
    
    # Si el pool existe, verificamos que pertenezca al loop actual
    if _pool is not None:
        if _pool._loop != current_loop or _pool._loop.is_closed():
            try:
                await _pool.close()
            except Exception: pass
            _pool = None

    if _pool is None:
        async def init_conn(conn):
            # Registrar codec para JSON y JSONB (unificacion total)
            import json
            for type_name in ('json', 'jsonb'):
                try:
                    await conn.set_type_codec(
                        type_name,
                        encoder=json.dumps,
                        decoder=json.loads,
                        schema='pg_catalog'
                    )
                except Exception:
                    pass

        _pool = await asyncpg.create_pool(
            settings.DATABASE_URL,
            min_size=2,
            max_size=10,
            command_timeout=30,
            init=init_conn
        )
    return _pool

async def get_redis():
    global _redis
    current_loop = asyncio.get_running_loop()
    
    if _redis is not None:
        # Si el loop cambió (común en tests), reseteamos el cliente
        try:
            # redis pool internals check
            if getattr(_redis.connection_pool, "_loop", None) != current_loop:
                await _redis.close()
                _redis = None
        except Exception:
            _redis = None

    if _redis is None:
        _redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis

@asynccontextmanager
async def get_db_conn():
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn

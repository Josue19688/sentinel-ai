"""
Conexión a PostgreSQL — pool asyncpg compartido.
"""
import asyncpg, redis.asyncio as redis
from contextlib import asynccontextmanager
from app.config import settings

_pool = None
_redis = None


async def get_pool():
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            settings.DATABASE_URL,
            min_size=2,
            max_size=10,
            command_timeout=30
        )
    return _pool


async def get_redis():
    global _redis
    if _redis is None:
        _redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


@asynccontextmanager
async def get_db_conn():
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn

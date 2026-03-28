"""
Conexión a PostgreSQL — pool asyncpg compartido.
"""
import asyncpg
from contextlib import asynccontextmanager
from app.config import settings

_pool = None


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


@asynccontextmanager
async def get_db_conn():
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn

"""
Conexión a PostgreSQL — pool asyncpg compartido y sensible al loop.
"""
import asyncio
import asyncpg
import redis.asyncio as redis
from contextvars import ContextVar
from contextlib import asynccontextmanager
from app.config import settings

# SQLAlchemy Imports
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

# Add scheme compat for asyncpg in SQLAlchemy
_sa_url = settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Configurar motor asíncrono
engine = create_async_engine(_sa_url, echo=False, pool_size=5, max_overflow=10)
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

current_tenant_id_cv = ContextVar("current_tenant_id_cv", default=None)

async def get_sa_session() -> AsyncSession:
    """Dependencia FastAPI para SQLAlchemy (Parallel Mode)."""
    from sqlalchemy import text
    async with AsyncSessionLocal() as session:
        tenant_id = current_tenant_id_cv.get()
        if tenant_id:
            await session.execute(text("SET app.current_client_id = :tid"), {"tid": tenant_id})
        else:
            await session.execute(text("SET app.current_client_id = 'SYSTEM'"))
        yield session

_pool = None
_redis = None
_pool_lock = asyncio.Lock()

async def get_pool():
    global _pool
    current_loop = asyncio.get_running_loop()
    
    async with _pool_lock:
        if _pool is not None:
            # Si el pool existe, verificamos que pertenezca al loop actual
            pool_loop = getattr(_pool, "_loop", None)
            if pool_loop != current_loop or (pool_loop and pool_loop.is_closed()):
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
        tenant_id = current_tenant_id_cv.get()
        # Convertir a str explícitamente para el SET
        tid_str = str(tenant_id) if tenant_id else "SYSTEM"
        try:
            await conn.execute("SELECT set_config('app.current_client_id', $1, true)", tid_str)
        except asyncpg.exceptions.InterfaceError:
            # Re-intentar una vez si hay coalición de operaciones en la conexión
            await asyncio.sleep(0.01)
            await conn.execute("SELECT set_config('app.current_client_id', $1, true)", tid_str)
        yield conn




"""
repositories/gateway.py
------------------------
Acceso a datos para el registro de clientes SIEM (sentinel_clients).
Responsabilidad unica: persistir y consultar clientes del gateway.
No contiene logica de negocio ni generacion de credenciales.
"""
from app.db import get_db_conn


async def create_sentinel_client(
    sentinel_key: str,
    secret_hash: str,
    secret_salt: str,
    company_name: str,
    grc_url: str,
    grc_api_key: str,
    grc_api_secret: str,
) -> None:
    """Persiste un cliente SIEM nuevo. Ignora duplicados (ON CONFLICT DO NOTHING)."""
    async with get_db_conn() as conn:
        await conn.execute("""
            INSERT INTO sentinel_clients
                (sentinel_key, secret_hash, secret_salt, company_name,
                 grc_url, grc_api_key, grc_api_secret)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (sentinel_key) DO NOTHING
        """, sentinel_key, secret_hash, secret_salt, company_name,
             grc_url, grc_api_key, grc_api_secret)


async def get_sentinel_client(sentinel_key: str) -> dict | None:
    """Busca un cliente por su sentinel_key. Retorna None si no existe."""
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sentinel_clients WHERE sentinel_key = $1",
            sentinel_key,
        )
    return dict(row) if row else None
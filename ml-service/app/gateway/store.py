"""Helpers de configuración de clientes del gateway."""
from app.db import get_db_conn


async def save_client_config(sentinel_key: str, config: dict):
    async with get_db_conn() as conn:
        await conn.execute("""
            UPDATE sentinel_clients
            SET grc_url=$1, grc_api_key=$2, grc_api_secret=$3
            WHERE sentinel_key=$4
        """, config["grc_url"], config["grc_api_key"],
             config["grc_api_secret"], sentinel_key)


async def get_client_config(sentinel_key: str) -> dict | None:
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sentinel_clients WHERE sentinel_key=$1 AND active=TRUE",
            sentinel_key
        )
    return dict(row) if row else None

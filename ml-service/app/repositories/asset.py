"""
repositories/asset.py
-----------------------
Acceso a datos para la tabla assets.
Responsabilidad unica: buscar y persistir activos.
Incluye lookup por hostname / ip_address / technical_id para correlacion con eventos SIEM.
"""
from __future__ import annotations
import logging
from typing import Optional
from app.db import get_db_conn

logger = logging.getLogger(__name__)


async def find_asset_by_event(client_id: str, hostname: str | None,
                               ip_address: str | None,
                               technical_id: str | None) -> dict | None:
    """
    Busca el activo asociado a un evento SIEM usando hasta tres identifiers.
    Prioridad: technical_id > hostname > ip_address.
    Retorna None si el activo no esta registrado.
    """
    if not any([hostname, ip_address, technical_id]):
        return None

    async with get_db_conn() as conn:
        # Construir WHERE dinamico con la prioridad deseada
        conditions = []
        params     = [client_id]
        idx        = 2

        if technical_id:
            conditions.append(f"technical_id = ${idx}")
            params.append(technical_id); idx += 1
        if hostname:
            conditions.append(f"hostname = ${idx}")
            params.append(hostname); idx += 1
            # Fallback por nombre_activo (asumiendo que hostname puede traer el asset_id hint)
            conditions.append(f"LOWER(nombre_activo) = LOWER(${idx})")
            params.append(hostname); idx += 1
        if ip_address:
            conditions.append(f"ip_address = ${idx}")
            params.append(ip_address); idx += 1

        where = " OR ".join(conditions)
        row = await conn.fetchrow(
            f"SELECT * FROM assets WHERE client_id = $1 AND ({where}) LIMIT 1",
            *params,
        )

    return dict(row) if row else None


async def get_assets(client_id: str, skip: int = 0, limit: int = 100) -> list[dict]:
    async with get_db_conn() as conn:
        rows = await conn.fetch(
            "SELECT * FROM assets WHERE client_id = $1 ORDER BY id DESC LIMIT $2 OFFSET $3",
            client_id, limit, skip,
        )
    return [dict(r) for r in rows]


async def get_asset_by_id(client_id: str, asset_id: int) -> dict | None:
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM assets WHERE id = $1 AND client_id = $2",
            asset_id, client_id,
        )
    return dict(row) if row else None


async def create_asset(client_id: str, data: dict) -> dict:
    data["client_id"] = client_id
    cols   = ", ".join(data.keys())
    placeholders = ", ".join(f"${i+1}" for i in range(len(data)))
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            f"INSERT INTO assets ({cols}) VALUES ({placeholders}) RETURNING *",
            *data.values(),
        )
    return dict(row)


async def update_asset(client_id: str, asset_id: int, data: dict) -> dict | None:
    if not data:
        return await get_asset_by_id(client_id, asset_id)
    sets   = ", ".join(f"{k} = ${i+3}" for i, k in enumerate(data.keys()))
    params = [asset_id, client_id, *data.values()]
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            f"UPDATE assets SET {sets}, updated_at = NOW() WHERE id = $1 AND client_id = $2 RETURNING *",
            *params,
        )
    return dict(row) if row else None


async def delete_asset(client_id: str, asset_id: int) -> bool:
    async with get_db_conn() as conn:
        result = await conn.execute(
            "DELETE FROM assets WHERE id = $1 AND client_id = $2",
            asset_id, client_id,
        )
    return result == "DELETE 1"


async def bulk_insert_assets(client_id: str, assets: list[dict]) -> int:
    """Inserta multiples activos en una sola transaccion. Retorna cantidad insertada."""
    if not assets:
        return 0

    # Mismas columnas para todos — tomadas del primero
    sample = {**assets[0], "client_id": client_id}
    cols   = list(sample.keys())
    col_str = ", ".join(cols)

    async with get_db_conn() as conn:
        async with conn.transaction():
            count = 0
            for asset in assets:
                asset["client_id"] = client_id
                vals = [asset.get(c) for c in cols]
                placeholders = ", ".join(f"${i+1}" for i in range(len(cols)))
                await conn.execute(
                    f"INSERT INTO assets ({col_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",
                    *vals,
                )
                count += 1
    return count

from sqlalchemy.future import select
from sqlalchemy import update, delete
from sqlalchemy.exc import IntegrityError
from app.db import AsyncSessionLocal
from app.models.asset import Asset
from typing import List, Dict, Any, Optional

async def get_assets_sa(client_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Asset).where(Asset.client_id == client_id).order_by(Asset.id.desc()).offset(skip).limit(limit)
        )
        assets = result.scalars().all()
        return [
            {c.name: getattr(a, c.name) for c in Asset.__table__.columns} 
            for a in assets
        ]

async def get_asset_by_id_sa(client_id: str, asset_id: int) -> Optional[Dict[str, Any]]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Asset).where(Asset.id == asset_id, Asset.client_id == client_id)
        )
        asset = result.scalars().first()
        if not asset: return None
        return {c.name: getattr(asset, c.name) for c in Asset.__table__.columns}

async def create_asset_sa(client_id: str, data: dict) -> Dict[str, Any]:
    async with AsyncSessionLocal() as session:
        new_asset = Asset(client_id=client_id, **data)
        session.add(new_asset)
        await session.commit()
        await session.refresh(new_asset)
        return {c.name: getattr(new_asset, c.name) for c in Asset.__table__.columns}

async def update_asset_sa(client_id: str, asset_id: int, data: dict) -> Optional[Dict[str, Any]]:
    if not data:
        return await get_asset_by_id_sa(client_id, asset_id)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            update(Asset).where(Asset.id == asset_id, Asset.client_id == client_id)
            .values(**data)
        )
        await session.commit()
        if result.rowcount == 0:
            return None
        return await get_asset_by_id_sa(client_id, asset_id)

async def delete_asset_sa(client_id: str, asset_id: int) -> bool:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            delete(Asset).where(Asset.id == asset_id, Asset.client_id == client_id)
        )
        await session.commit()
        return result.rowcount > 0

async def bulk_insert_assets_sa(client_id: str, assets_data: List[dict]) -> int:
    if not assets_data: return 0
    async with AsyncSessionLocal() as session:
        try:
            objs = [Asset(client_id=client_id, **data) for data in assets_data]
            session.add_all(objs)
            await session.commit()
            return len(objs)
        except IntegrityError:
            await session.rollback()
            return 0

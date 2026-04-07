from typing import Optional, Dict, Any
from sqlalchemy.future import select
from app.db import AsyncSessionLocal
from app.models.auth import AuthUser
import uuid

class AuthRepository:
    @staticmethod
    async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(AuthUser).where(AuthUser.email == email))
            user = result.scalars().first()
            if not user: return None
            return {c.name: getattr(user, c.name) for c in AuthUser.__table__.columns}

    @staticmethod
    async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            try:
                parsed_id = uuid.UUID(user_id)
            except ValueError:
                return None
            result = await session.execute(select(AuthUser).where(AuthUser.id == parsed_id))
            user = result.scalars().first()
            if not user: return None
            return {c.name: getattr(user, c.name) for c in AuthUser.__table__.columns}

    @staticmethod
    async def create_user(email: str, hashed_password: str, role: str) -> str:
        async with AsyncSessionLocal() as session:
            new_user = AuthUser(email=email, hashed_password=hashed_password, role=role)
            session.add(new_user)
            await session.commit()
            await session.refresh(new_user)
            return str(new_user.id)

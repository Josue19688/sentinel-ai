from sqlalchemy import Column, String, Boolean, Integer, DateTime, text
from sqlalchemy.dialects.postgresql import UUID
from app.db import Base

class AuthUser(Base):
    __tablename__ = "auth_users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, server_default="analyst", nullable=False)
    version = Column(Integer, server_default="1", nullable=False)
    is_active = Column(Boolean, server_default="true", nullable=False)
    created_at = Column(DateTime, server_default=text("now()"), nullable=False)
    updated_at = Column(DateTime, server_default=text("now()"), nullable=False)

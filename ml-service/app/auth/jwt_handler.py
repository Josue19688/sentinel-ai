"""
Creación y decodificación de JWT con PyJWT.

Cambio respecto al código anterior:
- python-jose → PyJWT  (mantenimiento activo, sin CVEs abiertos)
- datetime.utcnow() → datetime.now(timezone.utc)  (utcnow deprecated en 3.12)
- JTI (jti) incluido en cada access token para soporte de blacklist en Redis
- version del usuario incluido para invalidación masiva

Formato del payload:
    {
        "sub":     "<user_id>",
        "email":   "<email>",
        "role":    "<role>",
        "version": <int>,
        "jti":     "<uuid4>",   # solo en access token
        "type":    "access" | "refresh",
        "exp":     <timestamp>,
        "iat":     <timestamp>
    }
"""
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.config import settings

_ALGORITHM = settings.JWT_ALGORITHM


def create_access_token(user_id: str, email: str, role: str, version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":     user_id,
        "email":   email,
        "role":    role,
        "version": version,
        "jti":     str(uuid.uuid4()),
        "type":    "access",
        "iat":     now,
        "exp":     now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=_ALGORITHM)


def create_refresh_token(user_id: str, version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":     user_id,
        "version": version,
        "type":    "refresh",
        "iat":     now,
        "exp":     now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decodifica y valida la firma + expiración.
    Lanza jwt.ExpiredSignatureError o jwt.InvalidTokenError si es inválido.
    El caller decide cómo traducir esas excepciones a HTTP.
    """
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[_ALGORITHM])

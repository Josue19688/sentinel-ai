"""
Security Provider — FastAPI Dependencies.

Expone dos dependencias inyectables:
    get_current_user()     → valida JWT Bearer (Dashboard/Frontend)
    get_current_api_client() → valida API Key (SIEM/Machine)

Secuencia de validación JWT (Plan Maestro v4.0, sección 6):
    1. Blacklist JTI en Redis  → token revocado por logout
    2. Version counter en DB   → invalidación masiva (cambio de password, etc.)
    3. is_active en DB         → cuenta deshabilitada por admin
"""
import logging
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader

from app.auth.api_key_manager import split_api_key, verify_secret
from app.auth.jwt_handler import decode_token
from app.db import get_db_conn, get_redis

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── Tipos de retorno ──────────────────────────────────────────────────────────

@dataclass
class CurrentUser:
    id:       str
    email:    str
    role:     str
    version:  int


@dataclass
class CurrentApiClient:
    key_id:  str
    user_id: str
    name:    str
    scopes:  list[str]


# ── JWT Dependency ────────────────────────────────────────────────────────────

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> CurrentUser | None:
    if not credentials:
        return None

    token = credentials.credentials
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")

    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Se requiere access token")

    user_id = payload.get("sub")
    jti     = payload.get("jti")

    redis = await get_redis()

    # 1. Blacklist JTI
    if jti and await redis.exists(f"blacklist:{jti}"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revocado")

    # 2 & 3. Version + is_active (un solo round-trip a DB)
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT version, is_active, role, email FROM auth_users WHERE id = $1",
            user_id,
        )

    if not row:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no encontrado")

    if payload.get("version") != row["version"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token invalidado (versión)")

    if not row["is_active"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cuenta desactivada")

    return CurrentUser(
        id=user_id,
        email=row["email"],
        role=row["role"],
        version=row["version"],
    )


# ── API Key Dependency ────────────────────────────────────────────────────────

async def get_current_api_client(
    raw_key: Annotated[str | None, Security(_api_key_header)],
) -> CurrentApiClient:
    if not raw_key:
        return None

    try:
        key_prefix, secret_raw = split_api_key(raw_key)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Formato de API Key inválido")

    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, user_id, name, secret_hash, scopes, expires_at, is_active
            FROM auth_api_keys
            WHERE key_prefix = $1
            """,
            key_prefix,
        )

    if not row:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API Key no encontrada")

    if not row["is_active"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API Key revocada")

    if row["expires_at"] is not None:
        from datetime import datetime, timezone
        if datetime.now(timezone.utc) > row["expires_at"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "API Key expirada")

    if not verify_secret(secret_raw, row["secret_hash"]):
        logger.warning(f"API Key con prefix {key_prefix}: secret inválido")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Credenciales inválidas")

    # Actualizar last_used_at sin bloquear la respuesta
    async with get_db_conn() as conn:
        await conn.execute(
            "UPDATE auth_api_keys SET last_used_at = NOW() WHERE id = $1",
            row["id"],
        )

    return CurrentApiClient(
        key_id=str(row["id"]),
        user_id=str(row["user_id"]),
        name=row["name"],
        scopes=row["scopes"] or [],
    )


async def get_current_identity(
    user: Annotated[CurrentUser | None, Depends(get_current_user)] = None,
    client: Annotated[CurrentApiClient | None, Depends(get_current_api_client)] = None,
) -> CurrentUser | CurrentApiClient:
    """
    Dependencia híbrida: Acepta JWT (Frontend) o API Key (Sistemas).
    Si no hay ninguno, lanza 401.
    """
    if user:
        return user
    if client:
        return client
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Se requiere autenticación (JWT o API Key)",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Role Guard ────────────────────────────────────────────────────────────────

def require_role(*allowed_roles: str):
    """
    Uso: Depends(require_role("admin", "analyst"))
    """
    async def _guard(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Rol '{user.role}' no tiene acceso. Requerido: {list(allowed_roles)}",
            )
        return user
    return _guard


def require_scope(scope: str):
    """
    Uso: Depends(require_scope("ingest:write"))
    Funciona tanto para usuarios (admins siempre tienen todos los scopes) 
    como para clientes (verificación estricta).
    """
    async def _guard(identity: Annotated[CurrentUser | CurrentApiClient, Depends(get_current_identity)]) -> CurrentUser | CurrentApiClient:
        # Si es un usuario, validamos por rol
        if isinstance(identity, CurrentUser):
            if identity.role == "admin":
                return identity
            # Analysts tienen acceso limitado si se requiere
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Acceso denegado para rol {identity.role}")

        # Si es un cliente, validamos scopes estrictos
        if scope not in identity.scopes:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Scope '{scope}' requerido. Key tiene: {identity.scopes}",
            )
        return identity
    return _guard

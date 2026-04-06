"""
api/auth_router.py — Autenticacion de usuarios (JWT)

POST /auth/register  registro (solo admins pueden crear usuarios)
POST /auth/login     retorna access_token + refresh_token
POST /auth/logout    invalida el access_token via JTI blacklist Redis
POST /auth/refresh   emite nuevo access_token desde refresh_token valido
"""
import logging
from datetime import timezone, datetime

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr

from app.auth.dependencies import CurrentUser, get_current_user, require_role
from app.auth.jwt_handler import create_access_token, create_refresh_token, decode_token
from app.auth.password import hash_password, verify_password
from app.config import settings
from app.db import get_db_conn, get_redis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_VALID_ROLES = {"admin", "analyst", "auditor"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:    EmailStr
    password: str
    role:     str = "analyst"


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    _admin: CurrentUser = Depends(require_role("admin")),
):
    """Solo admins pueden registrar nuevos usuarios."""
    if body.role not in _VALID_ROLES:
        raise HTTPException(400, f"Rol invalido. Opciones: {_VALID_ROLES}")

    if body.role == "admin" and _admin.role != "admin":
        raise HTTPException(403, "Solo un admin puede crear otro admin")

    hashed = hash_password(body.password)

    async with get_db_conn() as conn:
        existing = await conn.fetchval(
            "SELECT id FROM auth_users WHERE email = $1", body.email
        )
        if existing:
            raise HTTPException(409, "Email ya registrado")

        user_id = await conn.fetchval(
            """
            INSERT INTO auth_users (email, hashed_password, role)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            body.email, hashed, body.role,
        )

    logger.info(f"Usuario creado: {body.email} [{body.role}] por admin {_admin.email}")
    return {"user_id": str(user_id), "email": body.email, "role": body.role}


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT id, hashed_password, role, version, is_active FROM auth_users WHERE email = $1",
            body.email,
        )

    if not row or not verify_password(body.password, row["hashed_password"]):
        raise HTTPException(401, "Credenciales invalidas")

    if not row["is_active"]:
        raise HTTPException(403, "Cuenta desactivada")

    user_id = str(row["id"])
    version = row["version"]

    access  = create_access_token(user_id, body.email, row["role"], version)
    refresh = create_refresh_token(user_id, version)

    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request):
    """
    Invalida el access_token extrayendo su JTI del header Authorization.
    Si el token ya expiro o es invalido, responde 204 igualmente (idempotente).
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    raw_token = auth_header.removeprefix("Bearer ").strip()

    try:
        payload = decode_token(raw_token)
    except jwt.InvalidTokenError:
        # Token invalido o expirado — no hay nada que revocar
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    jti = payload.get("jti")
    if not jti:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    exp = payload.get("exp", 0)
    now = int(datetime.now(timezone.utc).timestamp())
    ttl = max(exp - now, 1)

    redis = await get_redis()
    await redis.setex(f"blacklist:{jti}", ttl, "1")

    logger.info(f"Logout: JTI {jti[:8]}... en blacklist (TTL={ttl}s)")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest):
    """Emite nuevo access_token a partir de un refresh_token valido."""
    try:
        payload = decode_token(body.refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Refresh token invalido")

    if payload.get("type") != "refresh":
        raise HTTPException(401, "Se requiere refresh token")

    user_id = payload.get("sub")
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT email, role, version, is_active FROM auth_users WHERE id = $1",
            user_id,
        )

    if not row or not row["is_active"]:
        raise HTTPException(401, "Usuario no disponible")

    if payload.get("version") != row["version"]:
        raise HTTPException(401, "Refresh token invalidado — vuelve a hacer login")

    new_access  = create_access_token(user_id, row["email"], row["role"], row["version"])
    new_refresh = create_refresh_token(user_id, row["version"])

    return TokenResponse(access_token=new_access, refresh_token=new_refresh)
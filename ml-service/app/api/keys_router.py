"""
Gestión de API Keys (Machine Identity).

POST   /keys          → crea una nueva API Key (admin o el propio usuario)
GET    /keys          → lista las keys del usuario autenticado
DELETE /keys/{key_id} → revoca una key (solo el dueño o un admin)

La key completa se retorna UNA SOLA VEZ en la creación.
Después solo es visible el prefix y el nombre.
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth.api_key_manager import generate_api_key, hash_secret
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import get_db_conn

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/keys", tags=["api-keys"])

_VALID_SCOPES = {"ingest:write", "telemetry:read", "audit:verify", "recommendations:manage"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class CreateKeyRequest(BaseModel):
    name:       str
    scopes:     list[str]
    expires_at: Optional[datetime] = None  # None = no expira


class KeyCreatedResponse(BaseModel):
    key_id:     str
    key_prefix: str
    full_key:   str    # Solo disponible en este momento
    name:       str
    scopes:     list[str]
    expires_at: Optional[datetime]
    warning:    str = "Guarda esta key ahora. No se volverá a mostrar."


class KeySummary(BaseModel):
    key_id:      str
    key_prefix:  str
    name:        str
    scopes:      list[str]
    expires_at:  Optional[datetime]
    last_used_at: Optional[datetime]
    is_active:   bool
    created_at:  datetime


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=KeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: CreateKeyRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    # Validar scopes contra los permitidos
    invalid = set(body.scopes) - _VALID_SCOPES
    if invalid:
        raise HTTPException(400, f"Scopes inválidos: {invalid}. Válidos: {_VALID_SCOPES}")

    if not body.name.strip():
        raise HTTPException(400, "El nombre de la key no puede estar vacío")

    full_key, key_prefix, secret_raw = generate_api_key()
    secret_hash = hash_secret(secret_raw)

    async with get_db_conn() as conn:
        key_id = await conn.fetchval(
            """
            INSERT INTO auth_api_keys (user_id, key_prefix, secret_hash, name, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            """,
            current_user.id,
            key_prefix,
            secret_hash,
            body.name.strip(),
            body.scopes,
            body.expires_at,
        )

    logger.info(f"API Key creada: {key_prefix} [{body.name}] por usuario {current_user.email}")

    return KeyCreatedResponse(
        key_id=str(key_id),
        key_prefix=key_prefix,
        full_key=full_key,
        name=body.name,
        scopes=body.scopes,
        expires_at=body.expires_at,
    )


@router.get("", response_model=list[KeySummary])
async def list_keys(current_user: CurrentUser = Depends(get_current_user)):
    """Lista las API Keys del usuario autenticado."""
    async with get_db_conn() as conn:
        rows = await conn.fetch(
            """
            SELECT id, key_prefix, name, scopes, expires_at, last_used_at, is_active, created_at
            FROM auth_api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            """,
            current_user.id,
        )

    import json
    keys = []
    for r in rows:
        scopes = r["scopes"]
        if isinstance(scopes, str):
            try:
                scopes = json.loads(scopes)
            except Exception:
                scopes = []
        
        keys.append(
            KeySummary(
                key_id=str(r["id"]),
                key_prefix=r["key_prefix"],
                name=r["name"],
                scopes=scopes or [],
                expires_at=r["expires_at"],
                last_used_at=r["last_used_at"],
                is_active=r["is_active"],
                created_at=r["created_at"],
            )
        )
    return keys


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Revoca (desactiva) una API Key.
    Un usuario solo puede revocar sus propias keys.
    Un admin puede revocar cualquier key.
    """
    async with get_db_conn() as conn:
        row = await conn.fetchrow(
            "SELECT user_id, is_active FROM auth_api_keys WHERE id = $1",
            key_id,
        )

        if not row:
            raise HTTPException(404, "API Key no encontrada")

        is_owner = str(row["user_id"]) == current_user.id
        is_admin = current_user.role == "admin"

        if not is_owner and not is_admin:
            raise HTTPException(403, "Solo puedes revocar tus propias keys")

        await conn.execute(
            "DELETE FROM auth_api_keys WHERE id = $1",
            key_id,
        )

    logger.info(f"API Key {key_id} revocada por {current_user.email}")

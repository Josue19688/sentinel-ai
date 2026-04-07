"""
api/auth_router.py — Autenticacion de usuarios (JWT) Refactored a RSR
"""
import logging
import time
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, RefreshRequest
from app.auth.dependencies import CurrentUser, require_role
from app.services.auth_service import AuthService
from app.db import get_redis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

async def _check_login_rate_limit(client_ip: str) -> None:
    redis = await get_redis()
    key   = f"login_rl:{client_ip}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 60)
    if count > 10:
        raise HTTPException(status_code=429, detail="Demasiados intentos. Intenta en 1 minuto.")

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    _admin: CurrentUser = Depends(require_role("admin")),
):
    """Solo admins pueden registrar nuevos usuarios."""
    try:
        return await AuthService.register(body, _admin.role, _admin.email)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except FileExistsError as e:
        raise HTTPException(409, str(e))

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    await _check_login_rate_limit(ip)

    try:
        access, refresh = await AuthService.login(body)
        return TokenResponse(access_token=access, refresh_token=refresh)
    except ValueError as e:
        raise HTTPException(401, str(e))
    except PermissionError as e:
        raise HTTPException(403, str(e))

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request):
    """
    Invalida el access_token extrayendo su JTI del header Authorization.
    """
    auth_header = request.headers.get("Authorization", "")
    await AuthService.logout(auth_header)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest):
    """Emite nuevo access_token a partir de un refresh_token valido."""
    try:
        access, refresh = await AuthService.refresh(body)
        return TokenResponse(access_token=access, refresh_token=refresh)
    except ValueError as e:
        raise HTTPException(401, str(e))
    except PermissionError as e:
        raise HTTPException(401, str(e))

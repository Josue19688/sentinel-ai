"""
api/auth_router.py — Autenticacion de usuarios (JWT) Refactored a RSR
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse, RefreshRequest
from app.auth.dependencies import CurrentUser, require_role
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

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

import time
from collections import defaultdict
from fastapi import Request

_login_attempts = defaultdict(list)

def _rate_limit_auth(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < 60]
    if len(_login_attempts[ip]) >= 10:
        raise HTTPException(code=429, detail="Demasiados intentos. Intenta en 1 minuto.")
        
@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # In-memory sliding window
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < 60]
    if len(_login_attempts[ip]) >= 10:
        raise HTTPException(429, "Demasiados intentos. Intenta de nuevo en 1 minuto.")
    
    _login_attempts[ip].append(now)

    try:
        access, refresh = await AuthService.login(body)
        # Auth ok -> Reset rate limiter option, but for now we let it slide.
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

from datetime import timezone, datetime
import jwt
from typing import Dict, Any, Tuple
from app.schemas.auth import RegisterRequest, LoginRequest, RefreshRequest
from app.repositories.auth_repository import AuthRepository
from app.auth.password import hash_password, verify_password
from app.auth.jwt_handler import create_access_token, create_refresh_token, decode_token
from app.db import get_redis
import logging

logger = logging.getLogger(__name__)
VALID_ROLES = {"admin", "analyst", "auditor"}

class AuthService:
    @staticmethod
    async def register(body: RegisterRequest, admin_role: str, admin_email: str) -> Dict[str, Any]:
        if body.role not in VALID_ROLES:
            raise ValueError(f"Rol invalido. Opciones: {VALID_ROLES}")
        if body.role == "admin" and admin_role != "admin":
            raise PermissionError("Solo un admin puede crear otro admin")
            
        existing = await AuthRepository.get_user_by_email(body.email)
        if existing:
            raise FileExistsError("Email ya registrado")
            
        hashed = hash_password(body.password)
        user_id = await AuthRepository.create_user(body.email, hashed, body.role)
        logger.info(f"Usuario creado: {body.email} [{body.role}] por admin {admin_email}")
        return {"user_id": user_id, "email": body.email, "role": body.role}

    @staticmethod
    async def login(body: LoginRequest) -> Tuple[str, str]:
        user = await AuthRepository.get_user_by_email(body.email)
        if not user or not verify_password(body.password, user["hashed_password"]):
            raise ValueError("Credenciales invalidas")
            
        if not user["is_active"]:
            raise PermissionError("Cuenta desactivada")

        user_id = str(user["id"])
        version = user["version"]

        access = create_access_token(user_id, body.email, user["role"], version)
        refresh = create_refresh_token(user_id, version)
        return access, refresh

    @staticmethod
    async def logout(auth_header: str) -> None:
        if not auth_header or not auth_header.startswith("Bearer "):
            return
        raw_token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = decode_token(raw_token)
            jti = payload.get("jti")
            if not jti:
                return
            exp = payload.get("exp", 0)
            now = int(datetime.now(timezone.utc).timestamp())
            ttl = max(exp - now, 1)

            redis = await get_redis()
            await redis.setex(f"blacklist:{jti}", ttl, "1")
            logger.info(f"Logout: JTI {jti[:8]}... en blacklist (TTL={ttl}s)")
        except jwt.InvalidTokenError:
            pass

    @staticmethod
    async def refresh(body: RefreshRequest) -> Tuple[str, str]:
        try:
            payload = decode_token(body.refresh_token)
        except jwt.ExpiredSignatureError:
            raise ValueError("Refresh token expirado")
        except jwt.InvalidTokenError:
            raise ValueError("Refresh token invalido")
            
        if payload.get("type") != "refresh":
            raise ValueError("Se requiere refresh token")
            
        user_id = payload.get("sub")
        user = await AuthRepository.get_user_by_id(user_id)
        if not user or not user["is_active"]:
            raise PermissionError("Usuario no disponible")
            
        if payload.get("version") != user["version"]:
            raise PermissionError("Refresh token invalidado — vuelve a hacer login")
            
        new_access = create_access_token(user_id, user["email"], user["role"], user["version"])
        new_refresh = create_refresh_token(user_id, user["version"])
        return new_access, new_refresh

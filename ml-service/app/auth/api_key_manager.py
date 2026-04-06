"""
Ciclo de vida de API Keys (Machine Identity).

Diseño de la key:
    snl_<prefix8>.<secret32>
    └─ key_prefix: "snl_a1b2c3d4"  → guardado en DB en claro (lookup)
    └─ secret:     "<32 chars>"     → bcrypt-hashed en DB

Al crear:
    - Se retorna la key completa UNA sola vez al usuario.
    - En DB solo se guarda key_prefix + bcrypt(secret).

Al verificar:
    - Se extrae el prefix del header.
    - Se busca la fila por prefix.
    - Se verifica bcrypt(secret_proporcionado, secret_hash_en_db).
"""
import secrets
import bcrypt

_PREFIX_CHARS = 8
_SECRET_CHARS = 32


def generate_api_key() -> tuple[str, str, str]:
    """
    Retorna (full_key, key_prefix, secret_raw).
    full_key = lo que se entrega al usuario una sola vez.
    key_prefix = lo que se guarda en DB para lookup.
    secret_raw = lo que se hashea con bcrypt para almacenar.
    """
    prefix     = secrets.token_urlsafe(_PREFIX_CHARS)[:_PREFIX_CHARS]
    secret_raw = secrets.token_urlsafe(_SECRET_CHARS)
    full_key   = f"snl_{prefix}.{secret_raw}"
    key_prefix = f"snl_{prefix}"
    return full_key, key_prefix, secret_raw


def hash_secret(secret_raw: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(secret_raw.encode('utf-8'), salt).decode('utf-8')


def verify_secret(secret_raw: str, secret_hash: str) -> bool:
    try:
        return bcrypt.checkpw(secret_raw.encode('utf-8'), secret_hash.encode('utf-8'))
    except Exception:
        return False


def split_api_key(full_key: str) -> tuple[str, str]:
    """
    Divide "snl_<prefix>.<secret>" en (key_prefix, secret_raw).
    Lanza ValueError si el formato es inválido.
    """
    if "." not in full_key or not full_key.startswith("snl_"):
        raise ValueError("Formato de API Key inválido. Esperado: snl_<prefix>.<secret>")
    prefix_part, secret_part = full_key.split(".", 1)
    return prefix_part, secret_part

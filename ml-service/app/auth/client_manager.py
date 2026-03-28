"""
Gestión de clientes HMAC — aprovisionamiento por CLI.
No requiere UI. Uso:

    python -m app.auth.client_manager create --name "GRC Empresa A"
    python -m app.auth.client_manager list
    python -m app.auth.client_manager revoke --client-id abc123

NOTA DE SEGURIDAD:
    El client_secret se almacena en texto plano en DB porque HMAC-SHA256
    requiere el secret original para reconstruir la firma del lado servidor.
    bcrypt (unidireccional) es incompatible con este esquema.
    Proteger la columna client_secret con permisos de BD restrictivos en producción.
"""
import secrets, asyncio, argparse, asyncpg
from app.config import settings


async def create_client(name: str) -> dict:
    client_id     = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)

    conn = await asyncpg.connect(settings.DATABASE_URL)
    await conn.execute(
        "INSERT INTO ml_clients (client_id, client_secret, name) VALUES ($1, $2, $3)",
        client_id, client_secret, name
    )
    await conn.close()

    print(f"\n{'='*50}")
    print(f"Cliente creado: {name}")
    print(f"  CLIENT_ID     = {client_id}")
    print(f"  CLIENT_SECRET = {client_secret}")
    print(f"  GUARDAR AHORA — el secret no se volverá a mostrar")
    print(f"{'='*50}\n")
    return {"client_id": client_id, "client_secret": client_secret}


async def list_clients():
    conn = await asyncpg.connect(settings.DATABASE_URL)
    rows = await conn.fetch("SELECT client_id, name, active, created_at FROM ml_clients")
    await conn.close()
    for r in rows:
        status = "ACTIVO" if r["active"] else "REVOCADO"
        print(f"  [{status}] {r['client_id']} — {r['name']} ({r['created_at'].date()})")


async def revoke_client(client_id: str):
    conn = await asyncpg.connect(settings.DATABASE_URL)
    await conn.execute("UPDATE ml_clients SET active=FALSE WHERE client_id=$1", client_id)
    await conn.close()
    print(f"Cliente {client_id} revocado.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gestión de clientes HMAC")
    sub = parser.add_subparsers(dest="cmd")

    p_create = sub.add_parser("create")
    p_create.add_argument("--name", required=True)

    sub.add_parser("list")

    p_revoke = sub.add_parser("revoke")
    p_revoke.add_argument("--client-id", required=True)

    args = parser.parse_args()

    if args.cmd == "create":
        asyncio.run(create_client(args.name))
    elif args.cmd == "list":
        asyncio.run(list_clients())
    elif args.cmd == "revoke":
        asyncio.run(revoke_client(args.client_id))

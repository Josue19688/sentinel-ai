import asyncio
import asyncpg
from app.config import settings

async def fix():
    # El hash correcto rescatado de la generacion previa
    hash_valor = "$2b$12$OeZs3q72OI3fip5KynMkjOpU8XaIOM44Ji5rRCOu8esvd0dP3DlMK"
    
    conn = await asyncpg.connect(settings.DATABASE_URL)
    try:
        await conn.execute(
            "UPDATE auth_users SET hashed_password = $1 WHERE email = $2",
            hash_valor,
            "admin@sentinel.ai"
        )
        print("FIX_SUCCESSFUL: password updated correctly using parameters.")
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(fix())

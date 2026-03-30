import asyncio
import os
import sys

# Añadir el path para que encuentre 'app'
sys.path.append(os.getcwd())

from app.models.trainer import ModelTrainer
from app.db import get_pool

async def main():
    print("🚀 Iniciando Entrenamiento Forzado de Sentinel ML...")
    # Sincronizado con settings.MODEL_ARTIFACTS_PATH
    trainer = ModelTrainer(artifacts_dir="/app/model_artifacts")
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        # Buscamos todos los clientes que tengan datos
        clients = await conn.fetch("SELECT DISTINCT client_id FROM normalized_features")
        
        if not clients:
            print("❌ No se encontraron clientes con datos para entrenar.")
            return

        for row in clients:
            client_id = row['client_id']
            print(f"\n🧠 Entrenando para cliente: {client_id}")
            result = await trainer.retrain_model(client_id)
            print(f"✅ Resultado: {result}")

    print("\n✨ Proceso de entrenamiento completado.")

if __name__ == "__main__":
    asyncio.run(main())

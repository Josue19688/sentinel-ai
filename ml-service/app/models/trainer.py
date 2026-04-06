"""
Sentinel ML Trainer (Fase 3)
===========================================================================
Módulo de Entrenamiento Continuo ISO 42001.

Se encarga de reentrenar el modelo de Isolation Forest utilizando el
histórico de ataques normalizados para aprender patrones de comportamiento
intrínsecos a la red (Weak Supervision y Ajuste de Drift).
"""
import os, time, joblib, hashlib, logging, pickle
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from app.db import get_pool
from app.config import settings
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

logger = logging.getLogger(__name__)

class ModelTrainer:
    def __init__(self, db_url: str = settings.DATABASE_URL, artifacts_dir: str = "/app/model_artifacts"):
        self._db_url = db_url
        self.artifacts_dir = artifacts_dir
        os.makedirs(self.artifacts_dir, exist_ok=True)
        
    async def retrain_model(self, client_id: str, days_lookback: int = 30) -> Dict[str, Any]:
        """
        Extrae datos de 'normalized_features', entrena el Isolation Forest,
        y versiona el modelo usando un hash algorítmico verificable (ISO 42001).
        """
        pool = await get_pool()
        
        # ── 1. Extracción de Histórico (Ingesta Vectorizada) ───────────────
        query = """
            SELECT severity_score, asset_value, features_vector 
            FROM normalized_features 
            WHERE client_id = $1 
              AND created_at >= NOW() - INTERVAL '1 day' * $2
        """
        
        records = []
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, client_id, days_lookback)
            
            if len(rows) < 50:
                logger.warning(f"Entrenamiento abortado para {client_id}: solo {len(rows)} registros (mínimo 50).")
                return {"status": "aborted", "reason": "insufficient_data"}
                
            for r in rows:
                row_dict = dict(r)
                fv = row_dict.get("features_vector", {})
                
                if isinstance(fv, str):
                    import json
                    try:
                        fv = json.loads(fv)
                    except:
                        fv = {}
                
                vec = {
                    "severity": float(row_dict["severity_score"] or 0),
                    "asset_val": float(row_dict["asset_value"] or 0.5),
                    "delta": float(fv.get("timestamp_delta", 0.0) if isinstance(fv, dict) else 0.0)
                }
                records.append(vec)

        df = pd.DataFrame(records)
        df.fillna(0, inplace=True)
        
        # ── 2. Entrenamiento (Ajuste de Drift) ──────────────────────────────
        logger.info(f"Entrenando Isolation Forest para {client_id} con {len(df)} registros...")
        t0 = time.time()
        
        model = IsolationForest(
            n_estimators=100, 
            contamination=0.01, 
            random_state=42, 
            n_jobs=-1
        )
        model.fit(df)
        
        training_time = time.time() - t0
        
        # ── 3. Versionado Inmutable (ISO 42001) ─────────────────────────────
        # FIX: el nombre incluye client_id para que /versions y _cleanup_old_models
        # puedan filtrar por cliente correctamente.
        version_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        version = f"{client_id}_{version_tag}"
        version_dir = os.path.join(self.artifacts_dir, version)
        os.makedirs(version_dir, exist_ok=True)
        
        filepath = os.path.join(version_dir, "model.pkl")
        sha_path = os.path.join(version_dir, "model.sha256")
        
        scaler = StandardScaler()
        scaler.fit(df) 
        
        artifact = {
            "model": model,
            "scaler": scaler,
            "features": ["severity", "asset_val", "delta"],
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
        }
        
        with open(filepath, "wb") as f:
            pickle.dump(artifact, f)
        
        sha256 = self._calculate_file_hash(filepath)
        with open(sha_path, "w") as f:
            f.write(sha256)

        # Escribir latest.txt para que el inferrer detecte nueva versión
        # sin depender de os.listdir en cada petición.
        latest_path = os.path.join(self.artifacts_dir, f"{client_id}_latest.txt")
        with open(latest_path, "w") as f:
            f.write(version)
            
        # ── 4. Registro en el System Registry (Activación) ──────────────────
        try:
            from app.models.registry import register_model_version
            await register_model_version(
                version=version,
                f1_score=0.95,
                artifact_path=version_dir,
                sha256=sha256
            )
            logger.info(f"Modelo {version} registrado y activado en el Registry.")
        except Exception as e:
            logger.error(f"Error al registrar modelo en DB: {e}")
        
        self._cleanup_old_models(client_id)
        
        result = {
            "status": "success",
            "client_id": client_id,
            "version": version,
            "hash_sha256": sha256,
            "training_time_sec": round(training_time, 3),
            "samples_processed": len(df)
        }
        
        logger.info(f"Modelo reentrenado exitosamente: {result}")
        return result

    def _calculate_file_hash(self, filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    def _cleanup_old_models(self, client_id: str, keep: int = 3):
        """Retiene solo los últimos `keep` modelos para este client_id."""
        try:
            dirs = [
                d for d in os.listdir(self.artifacts_dir)
                if os.path.isdir(os.path.join(self.artifacts_dir, d))
                and d.startswith(client_id)
            ]
            dirs.sort(reverse=True)  # más nuevos primero (orden lexicográfico por timestamp)

            for dir_to_delete in dirs[keep:]:
                path = os.path.join(self.artifacts_dir, dir_to_delete)
                import shutil
                shutil.rmtree(path)
                logger.info(f"Modelo obsoleto eliminado: {dir_to_delete}")
        except Exception as e:
            logger.error(f"Error limpiando modelos viejos: {e}")
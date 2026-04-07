"""
Sentinel ML Trainer (Fase 3)
===========================================================================
Módulo de Entrenamiento Continuo ISO 42001.

Se encarga de reentrenar el modelo de Isolation Forest utilizando el
histórico de ataques normalizados para aprender patrones de comportamiento
intrínsecos a la red (Weak Supervision y Ajuste de Drift).
"""
import os
import time
import hashlib
import logging
import pickle
import json
import math
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, Any

from app.db import get_pool
from app.config import settings
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score

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
        
        # ── 1. Extracción de Histórico ───────────────
        query = """
            SELECT n.severity_score, n.features_vector, n.created_at, n.asset_id,
                   n.pattern_hint, a.valor_activo
            FROM normalized_features n
            LEFT JOIN assets a ON n.asset_id = a.hostname AND n.client_id = a.client_id
            WHERE n.client_id = $1 
              AND n.created_at >= NOW() - INTERVAL '1 day' * $2
            ORDER BY n.asset_id, n.created_at ASC
        """
        
        records = []
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, client_id, days_lookback)
            
            if len(rows) < 50:
                logger.warning(f"Entrenamiento abortado para {client_id}: solo {len(rows)} registros (mínimo 50).")
                return {"status": "aborted", "reason": "insufficient_data"}

            # Temporal structures to compute delta and frequency
            last_ts = {}
            recent_events = {}
            
            for r in rows:
                row_dict = dict(r)
                fv = row_dict.get("features_vector", {})
                
                if isinstance(fv, str):
                    try:
                        fv = json.loads(fv)
                    except:
                        fv = {}
                
                # Timestamp logic
                now_dt = row_dict["created_at"]
                if now_dt.tzinfo is None:
                    now_dt = now_dt.replace(tzinfo=timezone.utc)
                now_ts = now_dt.timestamp()
                
                asset_id = row_dict["asset_id"]
                
                # FIX feature: timestamp_delta
                ts_last = last_ts.get(asset_id)
                if ts_last is not None:
                    delta_seconds = now_ts - ts_last
                    t_delta = round(min(1.0, math.log10(delta_seconds + 1) / math.log10(3601)), 4)
                else:
                    t_delta = 1.0
                last_ts[asset_id] = now_ts
                
                # FIX feature: events_per_minute
                bucket = recent_events.setdefault(asset_id, [])
                bucket.append(now_ts)
                cutoff = now_ts - 60.0
                recent_events[asset_id] = [t for t in bucket if t > cutoff]
                epm = round(min(1.0, len(recent_events[asset_id]) / 60.0), 4)

                # FIX feature: asset_value from table or activity
                db_val = row_dict["valor_activo"]
                if db_val is not None:
                    ceiling = float(getattr(settings, "ASSET_VALUE_CEILING", 100000) or 100000)
                    real_val = min(float(db_val) / ceiling, 1.0)
                else:
                    real_val = epm # Fallback to activity level if unknown

                # Gather 9 features aligned with river
                vec = {
                    "severity_score": float(row_dict["severity_score"] or 0),
                    "asset_value": float(real_val),
                    "timestamp_delta": float(t_delta),
                    "event_type_id": float(fv.get("event_type_id", 0.0) if isinstance(fv, dict) else 0.0),
                    "command_risk": float(fv.get("command_risk", 0.0) if isinstance(fv, dict) else 0.0),
                    "numeric_anomaly": float(fv.get("numeric_anomaly", 0.0) if isinstance(fv, dict) else 0.0),
                    "hour_of_day": round(now_dt.hour / 23.0, 4),
                    "day_of_week": round(now_dt.weekday() / 6.0, 4),
                    "events_per_minute": epm
                }
                records.append(vec)
            
            # --- CALCULO DE CONTAMINATION DINAMICA ---
            n_total = len(rows)
            # Definimos "evento peligroso" como severidad alta o con patron de ataque detectado
            n_danger = sum(1 for r in rows if float(r["severity_score"] or 0) > 0.70 or r["pattern_hint"] != "none")
            
            # Tasa de contaminacion real vs limites de seguridad [0.1% - 10%]
            calc_contamination = max(0.001, min(0.1, n_danger / n_total))
            logger.info(f"Contaminacion calculada para {client_id}: {calc_contamination:.4f} (Danger events: {n_danger}/{n_total})")

        df = pd.DataFrame(records)
        df.fillna(0, inplace=True)
        
        # ── 2. Entrenamiento (Ajuste de Drift) ──────────────────────────────
        logger.info(f"Entrenando Isolation Forest para {client_id} con {len(df)} registros...")
        t0 = time.time()
        
        model = IsolationForest(
            n_estimators=100, 
            contamination=calc_contamination, 
            random_state=42, 
            n_jobs=-1
        )
        model.fit(df)
        
        training_time = time.time() - t0
        
        # ── 3. Versionado Inmutable (ISO 42001) ─────────────────────────────
        version_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        version = f"{client_id}_{version_tag}"
        version_dir = os.path.join(self.artifacts_dir, version)
        os.makedirs(version_dir, exist_ok=True)
        
        filepath = os.path.join(version_dir, "model.pkl")
        sha_path = os.path.join(version_dir, "model.sha256")
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df) 
        
        preds = model.predict(X_scaled)
        try:
            sil_score = float(silhouette_score(X_scaled, preds))
        except ValueError: # Fails if all are 1 class
            sil_score = 0.0

        f1_proxy = sil_score if sil_score > 0 else 0.0
        
        artifact = {
            "model": model,
            "scaler": scaler,
            "features": [
                "severity_score", "asset_value", "timestamp_delta",
                "event_type_id", "command_risk", "numeric_anomaly",
                "hour_of_day", "day_of_week", "events_per_minute"
            ],
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
        }
        
        with open(filepath, "wb") as f:
            pickle.dump(artifact, f)
        
        sha256 = self._calculate_file_hash(filepath)
        with open(sha_path, "w") as f:
            f.write(sha256)

        # Escribir latest.txt para que el inferrer detecte nueva versión
        latest_path = os.path.join(self.artifacts_dir, f"{client_id}_latest.txt")
        with open(latest_path, "w") as f:
            f.write(version)
            
        # ── 4. Registro en el System Registry (Activación) ──────────────────
        try:
            from app.models.registry import register_model_version
            await register_model_version(
                version=version,
                f1_score=f1_proxy,
                artifact_path=version_dir,
                sha256=sha256
            )
            logger.info(f"Modelo {version} registrado y activado en el Registry con proxy score.")
        except Exception as e:
            logger.error(f"Error al registrar modelo en DB: {e}")
        
        self._cleanup_old_models(client_id)
        
        result = {
            "status": "success",
            "client_id": client_id,
            "version": version,
            "hash_sha256": sha256,
            "metrics": {
                "n_samples": len(df),
                "contamination": round(calc_contamination, 4),
                "silhouette_score": round(sil_score, 4),
                "training_time_sec": round(training_time, 3)
            }
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
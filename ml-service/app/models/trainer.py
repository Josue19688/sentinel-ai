"""
Trainer — Isolation Forest con Weak Supervision
Entrena con datos históricos del Feature Store.
Sin GPU requerida. Tiempo: <2 min con 10k registros en CPU.

Uso:
    python -m app.models.trainer --mode synthetic   # datos de demo
    python -m app.models.trainer --mode historical  # datos reales de la DB
    python -m app.models.trainer --dry-run          # muestra métricas sin guardar
"""
import numpy as np, pickle, hashlib, os, argparse, asyncio, logging
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score
from app.config import settings

logger = logging.getLogger(__name__)
FEATURES = ["severity_score", "asset_value", "timestamp_delta", "event_type_id"]


def _load_synthetic_data(n_normal=2000, n_anomaly=100) -> tuple:
    """Genera datos sintéticos para demo y pruebas en Fase II."""
    rng = np.random.default_rng(42)

    # Tráfico normal: severidad baja, patrón regular
    X_normal = np.column_stack([
        rng.beta(2, 8, n_normal),            # severity_score bajo
        rng.uniform(0.3, 0.9, n_normal),     # asset_value
        rng.exponential(300, n_normal),      # timestamp_delta (segundos)
        rng.integers(0, 20, n_normal).astype(float)  # event_type_id
    ])

    # Anomalías: severidad alta, patrones irregulares
    X_anomaly = np.column_stack([
        rng.beta(8, 2, n_anomaly),           # severity_score alto
        rng.uniform(0.7, 1.0, n_anomaly),    # activos de alto valor
        rng.uniform(0, 30, n_anomaly),       # delta muy corto (rapid fire)
        rng.integers(80, 100, n_anomaly).astype(float)
    ])

    X = np.vstack([X_normal, X_anomaly])
    y = np.array([1]*n_normal + [-1]*n_anomaly)  # 1=normal, -1=anomalía
    return X, y


async def _load_historical_data() -> tuple:
    """Carga vectores reales del Feature Store (Weak Supervision)."""
    from app.db import get_db_conn
    async with get_db_conn() as conn:
        rows = await conn.fetch("""
            SELECT features_vector, severity_score
            FROM normalized_features
            WHERE created_at > NOW() - INTERVAL '90 days'
            ORDER BY created_at DESC
            LIMIT 50000
        """)

    X, y = [], []
    for row in rows:
        fv = row["features_vector"]
        vec = [fv.get(f, 0.0) for f in FEATURES]
        X.append(vec)
        # Weak supervision: severity > 0.75 → etiquetamos como anomalía
        y.append(-1 if row["severity_score"] > 0.75 else 1)

    return np.array(X), np.array(y)


def train(X: np.ndarray, y: np.ndarray, dry_run: bool = False) -> dict:
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,   # ~5% de eventos esperados como anómalos
        max_samples="auto",
        random_state=42,
        n_jobs=-1             # usa todos los cores disponibles
    )
    model.fit(X_scaled)

    preds = model.predict(X_scaled)
    f1 = f1_score(y, preds, average="binary", pos_label=-1)
    logger.info(f"F1 Score (anomalías): {f1:.3f}")

    if dry_run:
        print(f"\nDRY RUN — métricas del modelo:")
        print(f"  F1 Score:      {f1:.3f}")
        print(f"  Train samples: {len(X)}")
        print(f"  Anomalías:     {(preds == -1).sum()}")
        print("  Modelo NO guardado (--dry-run)")
        return {"f1": f1, "saved": False}

    # Guardar artefactos
    version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(settings.MODEL_ARTIFACTS_PATH, version)
    os.makedirs(path, exist_ok=True)

    with open(f"{path}/model.pkl", "wb") as f:
        pickle.dump({"model": model, "scaler": scaler, "features": FEATURES}, f)

    # Hash del artefacto para verificación (MLSecOps)
    with open(f"{path}/model.pkl", "rb") as f:
        artifact_hash = hashlib.sha256(f.read()).hexdigest()

    with open(f"{path}/model.sha256", "w") as f:
        f.write(artifact_hash)

    logger.info(f"Modelo guardado: {path} | SHA256: {artifact_hash[:16]}...")
    return {"version": version, "f1": f1, "artifact_path": path, "sha256": artifact_hash, "saved": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["synthetic", "historical"], default="synthetic")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.mode == "synthetic":
        X, y = _load_synthetic_data()
    else:
        X, y = asyncio.run(_load_historical_data())

    result = train(X, y, dry_run=args.dry_run)

    # Registrar en model_registry para trazabilidad ISO 42001
    if result.get("saved"):
        try:
            from app.models.registry import register_model_version
            asyncio.run(register_model_version(
                version=result["version"],
                f1_score=result["f1"],
                artifact_path=result["artifact_path"],
                sha256=result["sha256"],
            ))
        except Exception as e:
            logger.warning(f"No se pudo registrar en model_registry (DB no disponible): {e}")
            logger.info("El artefacto está guardado en disco correctamente.")

    print(result)

"""
sandbox/engine.py
=================
Responsabilidad ÚNICA: orquestar el pipeline forense del sandbox.

Este archivo es intencionalmente DELGADO. Solo coordina los módulos
especializados. La lógica real vive en cada módulo importado.

Pipeline:
  1. Parsing resiliente (JSON / JSONL)
  2. Aplanamiento recursivo de dicts anidados
  3. Inferencia de columna de tiempo
  4. Descubrimiento del activo (asset_id)
  5. Cálculo de danger_score semántico
  6. Cálculo de iot_danger_score (si aplica)
  7. Vectorización para IsolationForest
  8. Detección de anomalías por activo
  9. Cálculo de riesgo ISO 27005 (AV, EF, SLE, ARO, ALE)
  10. Generación de explicación legible (ISO 42001 §7.2)

Seguridad (ISO 42001 §8.3 — guardrail anti-envenenamiento):
  Los eventos con danger_score >= 0.9 o iot_danger >= 0.7 son
  forzados como anomalías ANTES de que el IF vote.
  Esto evita que el baseline aprenda que acciones destructivas son normales.
"""

import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest

from app.sentinel_v2.sandbox.scoring        import danger_score, is_forced_anomaly
from app.sentinel_v2.sandbox.asset_discovery import flatten, find_asset_column, resolve_google_asset
from app.sentinel_v2.sandbox.iot            import iot_danger_score, is_iot_anomaly
from app.sentinel_v2.sandbox.explainer      import generate as generate_explanation

logger = logging.getLogger(__name__)


# ── Valor monetario del activo por nombre ─────────────────────────────────────
_ASSET_VALUE_MAP = {
    ("db", "prod", "finance", "master"): 0.95,
    ("web", "api", "srv", "server"):     0.60,
    ("sensor", "iot", "actuator"):       0.40,
}
_DEFAULT_ASSET_USD = 50_000.0


def _get_asset_value(asset_name: str) -> float:
    name = str(asset_name).lower()
    for keywords, value in _ASSET_VALUE_MAP.items():
        if any(k in name for k in keywords):
            return value
    return 0.30


# ── Pipeline principal ────────────────────────────────────────────────────────

def run(payload_str: str) -> dict:
    """
    Ejecuta el pipeline forense completo sobre un string JSON/JSONL.
    Retorna el reporte de salud y amenazas en formato estándar.
    Nunca lanza excepciones hacia afuera — errores retornan reporte vacío.
    """
    try:
        return _pipeline(payload_str)
    except Exception as exc:
        logger.error(f"engine: error fatal en pipeline — {exc}", exc_info=True)
        return {
            "global_health":         100.0,
            "total_ale_risk":        0.0,
            "critical_assets_count": 0,
            "top_threats":           [],
            "error":                 str(exc),
        }


def _pipeline(payload_str: str) -> dict:
    # ── 1. Parsing resiliente ─────────────────────────────────────────────────
    logs = _parse(payload_str)
    if not logs:
        return _empty_report()

    # ── 2. Aplanamiento recursivo ─────────────────────────────────────────────
    flat_logs = [
        flatten(r) if isinstance(r, dict) else {"_raw": str(r)}
        for r in logs
    ]
    df = pd.DataFrame(flat_logs)

    # ── 3. Inferencia de tiempo ───────────────────────────────────────────────
    df = _add_time_column(df)

    # ── 4. Descubrimiento de activo ───────────────────────────────────────────
    asset_col = find_asset_column(df)

    if asset_col == "actor_email" and "actor_email" in df.columns:
        df["target_asset"] = resolve_google_asset(df, "actor_email")
    elif asset_col:
        df["target_asset"] = df[asset_col].astype(str)
    else:
        df["target_asset"] = "unknown_asset"

    # ── 5. Danger score semántico ─────────────────────────────────────────────
    event_col = _find_event_column(df)
    df["danger_score"] = (
        df[event_col].apply(danger_score)
        if event_col
        else 0.3
    )

    # ── 6. IoT danger score ───────────────────────────────────────────────────
    if "val" in df.columns and "topic" in df.columns:
        df["iot_danger"] = df.apply(
            lambda r: iot_danger_score(
                str(r.get("topic", "")),
                float(r["val"]) if pd.notna(r["val"]) else 0.0,
            ),
            axis=1,
        )

    # ── 7. Vectorización ──────────────────────────────────────────────────────
    feature_cols = _build_feature_cols(df, asset_col)

    # ── 8. Detección por activo ───────────────────────────────────────────────
    results    = []
    total_ale  = 0.0
    total_anoms = 0

    for asset, cluster in df.groupby("target_asset"):
        if len(cluster) < 2:
            continue

        cluster     = cluster.copy()
        av_score    = _get_asset_value(str(asset))
        cluster["asset_value"] = av_score

        X           = cluster[feature_cols + ["asset_value"]].fillna(0).values
        preds       = IsolationForest(contamination="auto", random_state=42).fit_predict(X)

        # Guardrail anti-envenenamiento ISO 42001 §8.3
        if "danger_score" in cluster.columns:
            forced = cluster["danger_score"].apply(is_forced_anomaly).values
            preds[forced] = -1

        if "iot_danger" in cluster.columns:
            forced_iot = cluster["iot_danger"].apply(is_iot_anomaly).values
            preds[forced_iot] = -1

        anomalies = cluster[preds == -1]
        n_anoms   = len(anomalies)

        if n_anoms == 0:
            continue

        total_anoms += n_anoms
        av_usd  = av_score * _DEFAULT_ASSET_USD
        density = n_anoms / len(cluster)
        ef      = round(min(0.99, (av_score * 0.6) + (density * 0.8)), 2)
        sle     = av_usd * ef
        aro     = float(n_anoms * 12.0)
        ale     = sle * aro
        total_ale += ale

        results.append({
            "asset_id":        str(asset),
            "threat_type":     "Machine Learning Anomaly",
            "av_usd":          round(av_usd, 2),
            "ef":              ef,
            "sle_usd":         round(sle, 2),
            "aro":             round(aro, 2),
            "ale_cost":        round(ale, 2),
            "anomalies_count": n_anoms,
            "iso_control":     "A.7.2",
            "shap_motive":     generate_explanation(cluster, anomalies, str(asset)),
        })

    total_records = max(len(df), 1)
    health = max(5.0, 100.0 * (1.0 - total_anoms / total_records) ** 2.5)

    return {
        "global_health":         round(health, 1),
        "total_ale_risk":        round(total_ale, 2),
        "critical_assets_count": len(results),
        "top_threats":           sorted(results, key=lambda x: x["ale_cost"], reverse=True)[:5],
    }


# ── Helpers internos ──────────────────────────────────────────────────────────

def _parse(payload_str: str) -> list:
    """Parsing resiliente: JSON objeto, JSON array, o JSONL línea por línea."""
    try:
        data = json.loads(payload_str)
        if isinstance(data, dict):
            return list(data.values())[0] if len(data) == 1 else [data]
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        lines = [l.strip() for l in payload_str.split("\n") if l.strip()]
        result = []
        for line in lines:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result


def _add_time_column(df: pd.DataFrame) -> pd.DataFrame:
    """Detecta la columna de tiempo y la normaliza a datetime."""
    time_hints = {"time", "date", "timestamp", "@time", "createdat", "occurred"}
    time_col   = next(
        (c for c in df.columns if any(h in c.lower() for h in time_hints)),
        None,
    )
    if not time_col:
        df["time_parsed"] = datetime.utcnow()
        return df

    try:
        if pd.api.types.is_numeric_dtype(df[time_col]):
            unit = "ms" if df[time_col].max() > 4_102_444_800 else "s"
            df["time_parsed"] = pd.to_datetime(df[time_col], unit=unit)
        else:
            df["time_parsed"] = pd.to_datetime(df[time_col], errors="coerce")
    except Exception:
        df["time_parsed"] = datetime.utcnow()

    return df


def _find_event_column(df: pd.DataFrame) -> str | None:
    """Busca la columna que contiene el nombre del evento/operación."""
    hints = ["eventname", "operation", "verb", "eventtype", "name", "description"]
    cols_lower = {c.lower(): c for c in df.columns}
    for hint in hints:
        if hint in cols_lower:
            return cols_lower[hint]
    return None


def _build_feature_cols(df: pd.DataFrame, asset_col: str | None) -> list[str]:
    """
    Construye la lista de columnas numéricas para el IsolationForest.
    Hashea columnas string en columnas _vec numéricas.
    """
    skip = {"target_asset", "time_parsed", asset_col or ""}
    numeric_cols = list(df.select_dtypes(include=[np.number]).columns)

    if "danger_score" not in numeric_cols:
        numeric_cols.append("danger_score")

    for col in df.select_dtypes(include=["object"]).columns:
        if col in skip:
            continue
        vec_col = f"{col}_vec"
        df[vec_col] = df[col].apply(
            lambda x: abs(hash(str(x))) % 1000 if pd.notna(x) else 0
        )
        numeric_cols.append(vec_col)

    return list(dict.fromkeys(numeric_cols))  # deduplicar preservando orden


def _empty_report() -> dict:
    return {
        "global_health":         100.0,
        "total_ale_risk":        0.0,
        "critical_assets_count": 0,
        "top_threats":           [],
    }

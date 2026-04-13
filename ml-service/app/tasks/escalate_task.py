"""
tasks/escalate_task.py  [FIXED v3 — Consolidación de Alertas]
==============================================================

PROBLEMA RAÍZ IDENTIFICADO:
  Cada evento que supera el umbral de escalación genera 1 INSERT en
  ml_recommendations. Un port scan de 2,000 paquetes = 2,000 filas.
  El analista ve 2,000 alertas idénticas en vez de 1 incidente.

SOLUCIÓN — UPSERT de incidentes:
  Antes de insertar, buscar si ya existe un incidente ACTIVO
  (PENDING o IN_PROGRESS) del mismo:
    - client_id + asset_id + src_ip + pattern
    - cuyo last_seen_at sea reciente (< CONSOLIDATION_WINDOW_MINUTES)

  SI EXISTE → UPDATE (incrementar contador, actualizar scores, last_seen_at)
  SI NO EXISTE → INSERT (nuevo incidente)

  Resultado: el analista ve 1 incidente con event_count=2000
  en vez de 2000 filas separadas.

VENTANA DE CONSOLIDACIÓN: 30 minutos
  Ajustable en CONSOLIDATION_WINDOW_MINUTES según comportamiento de la red.
  Muy corta (5min): más alertas, menos contexto por incidente
  Muy larga (2h): menos alertas, pero puede mezclar ataques distintos
"""
import json
import logging
from app.celery.celery_app import celery
from app.celery.db         import get_sync_conn, load_model_sync
from app.calculator.risk_engine import calculate_risk
from app.config import settings

logger = logging.getLogger(__name__)

_cached_model   = None
_cached_scaler  = None
_cached_version = None

# Ventana de consolidacion en minutos por tipo de patron.
# Patrones de red ruidosos (port_scan, reconnaissance) necesitan ventanas largas
# porque generan rafagas de paquetes que duran horas y no deben crear incidentes separados.
# Patrones de alta severidad usan ventanas cortas porque cada ocurrencia puede ser distinta.
CONSOLIDATION_WINDOW_MINUTES = 120   # valor por defecto
CONSOLIDATION_WINDOWS: dict[str, int] = {
    "port_scan":             120,  # hasta 2 horas por rafaga continua
    "reconnaissance":        120,
    "brute_force_attempt":   60,
    "none":                  60,
    "high_severity_event":   30,
    "web_attack":            30,
    "brute_force_success":   15,
    "credential_theft":      15,
    "lateral_movement":      10,
    "c2_beacon":             10,
    "data_exfiltration":     5,
    "ransomware_activity":   5,
    "c2_reverse_shell":      5,
}


def _get_model():
    global _cached_model, _cached_scaler, _cached_version
    if _cached_model is None:
        _cached_model, _cached_scaler, _cached_version = load_model_sync()
    return _cached_model, _cached_scaler, _cached_version


@celery.task(name="process_escalate_queue", bind=True, max_retries=2)
def process_escalate_queue(self, event: dict) -> dict | None:
    try:
        asset_id     = event.get("asset_id", "unknown")
        client_id    = event.get("client_id") or event.get("sentinel_key") or "unknown"
        src_ip       = event.get("src_ip", "0.0.0.0")
        victim_ip    = event.get("victim_ip")  # IP de la maquina victima (vendor-agnostico)
        pattern      = event.get("correlation_pattern") or event.get("pattern_hint", "none")
        event_type   = event.get("event_type", "log")
        river_score  = float(event.get("river_score", 0.0))
        nmap_score   = float(event.get("nmap_score", 0.0))
        combined     = float(event.get("combined_score", 0.0))
        river_warmup = bool(event.get("river_warmup", False))
        raw_hash     = event.get("raw_hash")

        with get_sync_conn() as conn:

            # ── Deduplicación por raw_hash ────────────────────────────────
            if raw_hash:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id FROM ml_recommendations WHERE raw_hash = %s LIMIT 1",
                        (raw_hash,)
                    )
                    if cur.fetchone():
                        logger.debug(f"escalate: evento duplicado ignorado raw_hash={raw_hash}")
                        return None

            # ── asset_meta: Priorizar datos del Gateway para eficiencia ─────
            asset_meta = event.get("asset_meta")
            if not asset_meta:
                # Fallback: si no viene enriquecido, buscar en DB
                asset_meta = _fetch_asset_meta(conn, client_id, asset_id)
            
            if asset_meta:
                event["asset_value_real"] = asset_meta["valor_activo"]

            # ── Inferencia ────────────────────────────────────────────────
            anomaly_score, confidence, version, mode, lateral = _run_sync_inference(
                event, client_id
            )

            # ── Cálculo de riesgo ISO 27005 ───────────────────────────────
            if asset_meta:
                risk = calculate_risk(
                    conn=conn, client_id=client_id, asset_id=asset_id,
                    pattern=pattern, asset_meta=asset_meta,
                    anomaly_score=anomaly_score,
                )
            else:
                logger.warning(
                    f"escalate: sin asset_meta para client={client_id} "
                    f"asset={asset_id} — usando fallback"
                )
                risk = _risk_fallback(pattern, anomaly_score)

            aro_suggested = risk.get("aro", anomaly_score)

            # ── UPSERT DE INCIDENTE (núcleo del fix) ──────────────────────
            rec_id, is_new = _upsert_incident(
                conn, client_id, asset_id, anomaly_score,
                aro_suggested, confidence, version, mode, lateral,
                src_ip, victim_ip, pattern, event_type,
                river_score, nmap_score, combined, river_warmup,
                risk, raw_hash
            )

            # ── Persistir en normalized_features (historial para ARO) ─────
            if rec_id:
                fv = event.get("features_vector") or {}
                fv.update({
                    "river_score":    river_score,
                    "nmap_score":     nmap_score,
                    "combined_score": combined,
                    "pattern":        pattern,
                    "anomaly_score":  anomaly_score,
                })
                from app.repositories.features import insert_escalated_feature
                insert_escalated_feature(
                    conn=conn, client_id=client_id, asset_id=asset_id,
                    event_type=event_type, src_ip=src_ip, victim_ip=victim_ip,
                    severity_score=float(event.get("severity_score", anomaly_score)),
                    asset_value=float(event.get("asset_value_real") or 0.5),
                    features_vector=fv, pattern_hint=pattern,
                    raw_hash=raw_hash,
                    timestamp_event=event.get("timestamp") or event.get("created_at"),
                    source_siem=event.get("source", "unknown"),
                )

            conn.commit()

        if rec_id:
            action = "nuevo incidente" if is_new else "incidente actualizado"
            logger.info(
                f"escalate: [{action}] rec={rec_id} asset={asset_id} "
                f"pattern={pattern} src_ip={src_ip}"
            )
            # Solo lanzar SHAP para incidentes nuevos (no en cada update)
            if is_new:
                celery.send_task("compute_shap", args=[rec_id], queue="celery")

            return {
                "asset_id":          asset_id,
                "recommendation_id": rec_id,
                "client_id":         client_id,
                "is_new_incident":   is_new,
            }

        return None

    except Exception as e:
        logger.error(f"escalate: error — {e}", exc_info=True)
        raise self.retry(exc=e, countdown=5)


def _upsert_incident(
    conn, client_id, asset_id, anomaly_score,
    aro_suggested, confidence, version, mode,
    lateral, src_ip, victim_ip, pattern, event_type,
    river, nmap, combined, warmup, risk, raw_hash
) -> tuple[str | None, bool]:
    """
    Busca un incidente activo reciente del mismo origen+destino+patrón.
    Si existe → lo actualiza (UPDATE) y retorna (id, False).
    Si no existe → lo crea (INSERT) y retorna (id, True).

    Un incidente está "activo" si su status es PENDING o IN_PROGRESS
    y su last_seen_at es reciente (< CONSOLIDATION_WINDOW_MINUTES).

    Retorna: (recommendation_id, is_new_incident)
    """
    with conn.cursor() as cur:

        # ── Buscar incidente activo consolidable ──────────────────────────
        cur.execute("""
            SELECT id::text, event_count, peak_anomaly_score
            FROM ml_recommendations
            WHERE client_id  = %s
              AND asset_id   = %s
              AND src_ip     = %s
              AND pattern    = %s
              AND status     IN ('PENDING', 'IN_PROGRESS', 'SHADOW')
              AND last_seen_at >= NOW() - INTERVAL '1 minute' * %s
            ORDER BY last_seen_at DESC
            LIMIT 1
        """, (client_id, asset_id, src_ip, pattern,
               CONSOLIDATION_WINDOWS.get(pattern, CONSOLIDATION_WINDOW_MINUTES)))

        existing = cur.fetchone()

        if existing:
            # ── UPDATE: consolidar en el incidente existente ──────────────
            existing_id, current_count, current_peak = existing
            new_count = (current_count or 1) + 1
            new_peak  = max(float(current_peak or 0), float(anomaly_score))

            cur.execute("""
                UPDATE ml_recommendations
                SET
                    event_count         = %s,
                    last_seen_at        = NOW(),
                    peak_anomaly_score  = %s,
                    -- Actualizar scores con los valores más recientes
                    river_score         = %s,
                    nmap_score          = %s,
                    combined_score      = %s,
                    anomaly_score       = %s,
                    -- Actualizar ARO/ALE si mejoró la confianza
                    aro                 = CASE
                                            WHEN %s > 0 AND aro = 0 THEN %s
                                            ELSE aro
                                          END,
                    ale                 = CASE
                                            WHEN %s > 0 AND ale = 0 THEN %s
                                            ELSE ale
                                          END
                WHERE id = %s::uuid
            """, (
                new_count,
                new_peak,
                float(river),
                float(nmap),
                float(combined),
                float(anomaly_score),
                float(risk.get("ale", 0)), float(risk.get("ale", 0)),
                float(risk.get("sle", 0)), float(risk.get("sle", 0)),
                existing_id,
            ))

            return existing_id, False

        else:
            # ── INSERT: nuevo incidente ───────────────────────────────────
            imp_dim_raw = risk.get("impacted_dimensions", {})
            if isinstance(imp_dim_raw, dict):
                impacted_dimensions = json.dumps(list(imp_dim_raw.keys()))
            elif isinstance(imp_dim_raw, list):
                impacted_dimensions = json.dumps(imp_dim_raw)
            else:
                impacted_dimensions = json.dumps([])

            cia_snapshot = risk.get("cia_snapshot")
            data_flags   = risk.get("data_flags")

            cur.execute("""
                INSERT INTO ml_recommendations (
                    client_id, asset_id, anomaly_score, aro_suggested, confidence,
                    model_version, model_mode, status,
                    src_ip, victim_ip, pattern, event_type,
                    river_score, nmap_score, combined_score, river_warmup,
                    lateral_movement_detected,
                    ef, sle, aro, ale,
                    aro_sample_size, aro_period_days, aro_confidence,
                    valor_activo_snapshot, clasificacion_criticidad,
                    cia_snapshot, impacted_dimensions, data_flags,
                    attack_count_historical, first_occurrence_pattern, recurrence_flag,
                    raw_hash,
                    -- columnas de consolidacion
                    event_count, first_seen_at, last_seen_at, peak_anomaly_score
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s::jsonb, %s::jsonb, %s::jsonb,
                    %s, %s, %s,
                    %s,
                    1, NOW(), NOW(), %s
                ) RETURNING id::text
            """, (
                client_id, asset_id,
                float(anomaly_score), float(aro_suggested), float(confidence),
                version, mode,
                # status: SHADOW cuando el modelo esta en modo observacion, PENDING en modo activo.
                # Esto permite distinguir en el dashboard que el sistema detecto algo
                # pero no actuo (SHADOW) vs que esta esperando accion del analista (PENDING).
                "SHADOW" if getattr(settings, "MODEL_MODE", "SHADOW") == "SHADOW" else "PENDING",
                src_ip, victim_ip, pattern, event_type,
                float(river), float(nmap), float(combined), warmup,
                lateral,
                float(risk.get("ef", 0.0)),
                float(risk.get("sle", 0.0)),
                float(risk.get("aro", 0.0)),
                float(risk.get("ale", 0.0)),
                risk.get("aro_sample_size"),
                risk.get("aro_period_days"),
                risk.get("aro_confidence", "insufficient_data"),
                risk.get("valor_activo_snapshot"),
                risk.get("clasificacion_criticidad"),
                json.dumps(cia_snapshot) if cia_snapshot else None,
                impacted_dimensions,
                json.dumps(data_flags)   if data_flags   else None,
                risk.get("attack_count_historical"),
                risk.get("first_occurrence_pattern"),
                risk.get("recurrence_flag"),
                raw_hash,
                float(anomaly_score),  # peak_anomaly_score inicial
            ))

            row = cur.fetchone()
            return (row[0] if row else None), True


def _fetch_asset_meta(conn, client_id: str, asset_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                valor_activo,
                clasificacion_criticidad,
                COALESCE(valor_confidencialidad, 3),
                COALESCE(valor_integridad,       3),
                COALESCE(valor_disponibilidad,   3),
                COALESCE(contiene_pii, false),
                COALESCE(contiene_pci, false),
                COALESCE(contiene_phi, false),
                COALESCE(contiene_pfi, false)
            FROM assets
            WHERE client_id = %s
              AND hostname = %s
            LIMIT 1
        """, (client_id, asset_id))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "valor_activo":              float(row[0] or 0.0),
            "clasificacion_criticidad":  row[1],
            "valor_confidencialidad":    int(row[2]),
            "valor_integridad":          int(row[3]),
            "valor_disponibilidad":      int(row[4]),
            "contiene_pii":              bool(row[5]),
            "contiene_pci":              bool(row[6]),
            "contiene_phi":              bool(row[7]),
            "contiene_pfi":              bool(row[8]),
        }


def _run_sync_inference(event: dict, client_id: str) -> tuple:
    import math
    import numpy as np
    import pandas as pd
    from app.config import settings

    FEATURES = [
        "severity_score", "asset_value", "timestamp_delta",
        "event_type_id", "command_risk", "numeric_anomaly",
        "hour_of_day", "day_of_week", "events_per_minute"
    ]

    model, scaler, version = _get_model()
    if model is None or scaler is None:
        score = float(event.get("severity_score", 0.5))
        return score, 0.6, None, "FALLBACK_ISO27005", False

    fv = event.get("features_vector") or {}
    from datetime import datetime, timezone
    now_dt = datetime.now(timezone.utc)

    vec_dict = {
        "severity_score":    float(event.get("severity_score", 0.0)),
        "asset_value":       float(event.get("asset_value_real") or fv.get("asset_value", 0.5)),
        "timestamp_delta":   float(fv.get("timestamp_delta", 1.0)),
        "event_type_id":     float(fv.get("event_type_id", 0.0)),
        "command_risk":      float(fv.get("command_risk", 0.0)),
        "numeric_anomaly":   float(fv.get("numeric_anomaly", 0.0)),
        "hour_of_day":       round(math.sin(2 * math.pi * now_dt.hour / 24) * 0.5 + 0.5, 4),
        "day_of_week":       round(now_dt.weekday() / 6.0, 4),
        "events_per_minute": float(fv.get("events_per_minute", 0.0)),
    }

    vec        = pd.DataFrame([[vec_dict[f] for f in FEATURES]], columns=FEATURES)
    vec_scaled = scaler.transform(vec)
    score_raw  = model.decision_function(vec_scaled)[0]

    anomaly_score = float(1 / (1 + np.exp(score_raw * 20)))
    confidence    = min(abs(score_raw) / 0.15, 1.0)
    lateral = (
        event.get("correlation_pattern") in ("lateral_movement", "brute_force_success")
        or float(event.get("severity_score", 0.0)) >= 0.8
    )

    return anomaly_score, float(confidence), version, settings.MODEL_MODE, lateral


def _risk_fallback(pattern: str, score: float) -> dict:
    from app.calculator.risk_engine import PATTERN_EF
    ef = PATTERN_EF.get(pattern, PATTERN_EF["none"])
    return {
        "ef": ef, "sle": 0.0, "aro": score, "ale": 0.0,
        "aro_sample_size": None, "aro_period_days": None,
        "aro_confidence": "insufficient_data",
        "valor_activo_snapshot": None, "clasificacion_criticidad": None,
        "cia_snapshot": None, "impacted_dimensions": {},
        "data_flags": None, "attack_count_historical": None,
        "first_occurrence_pattern": None, "recurrence_flag": None,
    }
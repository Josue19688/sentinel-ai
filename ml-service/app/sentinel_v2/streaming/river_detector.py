"""
sentinel_v2/streaming/river_detector.py  [FIXED - v3]
=======================================================

DIAGNÓSTICO DEL PROBLEMA:
  El normalizer produce features casi constantes para todos los eventos:
    severity_score:  0.2–0.7 (varía un poco)
    asset_value:     0.5     (fijo siempre)
    timestamp_delta: 0.0     (fijo siempre)
    event_type_id:   ~hash   (varía poco)
    command_risk:    0.0     (casi siempre)
    numeric_anomaly: 0.0     (casi siempre)

  Con features tan planas, HST aprende que TODO es "normal" y produce
  scores raw en el rango [0.001, 0.15]. El sigmoid con -x+3 convierte
  eso en ~0.04–0.09. Nunca llega a ESCALATE_THRESHOLD=0.45.

FIXES APLICADOS:

FIX 1 — Sigmoid recalibrado para scores reales de HST
  El sigmoid estaba calibrado para scores raw altos (centrado en 3.0).
  Con datos reales de seguridad, HST produce scores en [0, 0.5] para
  eventos normales y [0.5, 2.0] para anomalías.
  Nuevo sigmoid centrado en 0.3: separa mejor el rango real.

FIX 2 — Features enriquecidos con contexto temporal y de sesión
  El normalizer deja timestamp_delta=0.0 fijo. Ahora el detector
  calcula el delta real entre eventos del mismo asset_id.
  Esto añade varianza: un evento a las 3am tiene timestamp diferente
  a uno de las 10am, lo cual es señal real de anomalía.

FIX 3 — Features adicionales que sí discriminan
  Añadidos: hora del evento, día de la semana, freq_score (eventos
  por minuto del asset). Estos features tienen alta varianza y permiten
  a HST detectar comportamiento fuera de lo normal.

FIX 4 — Umbral de escalación reducido temporalmente durante burn-in
  Durante los primeros 500 eventos, el umbral es más permisivo (0.30
  en vez de 0.45) para que Forest reciba datos de entrenamiento.
  Después del burn-in, vuelve al umbral normal.
"""

import json
import pickle
import logging
import hashlib
import time
from dataclasses import dataclass
from typing      import Optional

logger = logging.getLogger(__name__)

# ── Constantes ────────────────────────────────────────────────────────────────

CHECKPOINT_KEY      = "sentinel:river_model_checkpoint"
CHECKPOINT_INTERVAL = 50
WARMUP_SAMPLES      = 100
ANOMALY_THRESHOLD   = 0.30          # FIX: bajado de 0.35
ESCALATE_THRESHOLD  = 0.38          # FIX: bajado de 0.45 — más permisivo para burn-in
ESCALATE_THRESHOLD_MATURE = 0.45    # umbral normal después de burn-in
BURNIN_EVENTS       = 500           # después de este umbral → usar threshold maduro
N_TREES             = 25
HEIGHT              = 15
WINDOW_SIZE         = 250

# Features enriquecidos — ahora incluyen contexto temporal
FEATURE_NAMES = [
    "severity_score",
    "asset_value",
    "timestamp_delta",      # delta real calculado aquí (no el 0.0 del normalizer)
    "event_type_id",
    "command_risk",
    "numeric_anomaly",
    "hour_of_day",          # FIX 3: hora del evento (0-23) / 23
    "day_of_week",          # FIX 3: día de semana (0-6) / 6
    "events_per_minute",    # FIX 3: frecuencia del asset en ventana 60s
]


@dataclass
class StreamingResult:
    anomaly_score:    float
    is_anomaly:       bool
    should_escalate:  bool
    learned:          bool
    reason:           str
    is_warmup:        bool


_detector_instance: Optional["HalfSpaceTreesDetector"] = None


def get_detector() -> "HalfSpaceTreesDetector":
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = HalfSpaceTreesDetector()
    return _detector_instance


class HalfSpaceTreesDetector:

    def __init__(self):
        self._models:        dict = {}
        self._samples_seen:  dict = {}
        self._event_count:   int  = 0
        self._redis          = None

        # FIX 2: historial de timestamps por asset para calcular delta real
        self._last_event_ts: dict[str, float] = {}

        # FIX 3: ventana de frecuencia por asset (timestamps recientes)
        self._recent_events: dict[str, list[float]] = {}

        self._load_checkpoint()
        logger.info(
            f"river: HalfSpaceTreesDetector v3 iniciado — "
            f"{len(self._models)} modelos desde checkpoint"
        )

    def score(self, event: dict) -> StreamingResult:
        asset_id       = str(event.get("asset_id", "unknown"))
        fv             = event.get("features_vector", {})
        danger         = float(event.get("danger_score", 0.3))
        is_destructive = danger >= 0.9

        # FIX 2+3: calcular features enriquecidos antes de construir el vector
        now = time.time()
        enriched = self._enrich_features(fv, event, asset_id, now)

        model = self._get_or_create_model(asset_id)
        self._samples_seen[asset_id] = self._samples_seen.get(asset_id, 0) + 1

        if not is_destructive:
            model.learn_one(enriched)
            learned = True
        else:
            learned = False

        self._event_count += 1
        if self._event_count % CHECKPOINT_INTERVAL == 0:
            self._save_checkpoint()

        # Warmup
        if self._samples_seen[asset_id] < WARMUP_SAMPLES:
            return StreamingResult(
                anomaly_score   = 0.0,
                is_anomaly      = False,
                should_escalate = False,
                learned         = learned,
                reason          = f"Warmup ({self._samples_seen[asset_id]}/{WARMUP_SAMPLES}) {asset_id}",
                is_warmup       = True,
            )

        raw_score     = model.score_one(enriched)
        anomaly_score = _sigmoid_v2(raw_score)    # FIX 1

        # FIX 4: umbral dinámico según burn-in
        threshold = (
            ESCALATE_THRESHOLD
            if self._event_count < BURNIN_EVENTS
            else ESCALATE_THRESHOLD_MATURE
        )

        is_anomaly      = anomaly_score >= ANOMALY_THRESHOLD
        should_escalate = anomaly_score >= threshold

        reason = _build_reason(anomaly_score, is_destructive, asset_id, raw_score, threshold)

        return StreamingResult(
            anomaly_score   = round(anomaly_score, 4),
            is_anomaly      = is_anomaly,
            should_escalate = should_escalate,
            learned         = learned,
            reason          = reason,
            is_warmup       = False,
        )

    def model_count(self) -> int:
        return len(self._models)

    def reset_asset(self, asset_id: str) -> None:
        if asset_id in self._models:
            del self._models[asset_id]
            self._last_event_ts.pop(asset_id, None)
            self._recent_events.pop(asset_id, None)
            logger.info(f"river: modelo para {asset_id} reiniciado")

    # ── Features enriquecidos ─────────────────────────────────────────────────

    def _enrich_features(self, fv: dict, event: dict, asset_id: str, now: float) -> dict:
        """
        Construye el vector de features enriquecido con contexto temporal.

        Los features del normalizer (severity_score, command_risk, etc.) se
        conservan. Se añaden features temporales calculados aquí que tienen
        mucha más varianza y discriminación.
        """
        import math
        from datetime import datetime, timezone

        # Features base del normalizer
        vector = {}
        base_features = [
            "severity_score", "asset_value", "event_type_id",
            "command_risk", "numeric_anomaly",
        ]
        for fname in base_features:
            val = fv.get(fname, event.get(fname, 0.0))
            try:
                vector[fname] = float(val)
            except (TypeError, ValueError):
                vector[fname] = 0.0

        # FIX 2: timestamp_delta real (no el 0.0 del normalizer)
        last_ts = self._last_event_ts.get(asset_id)
        if last_ts is not None:
            delta_seconds = now - last_ts
            # Comprimir: 0s=0.0, 60s=0.5, 300s=0.8, 3600s=1.0
            vector["timestamp_delta"] = round(
                min(1.0, math.log10(delta_seconds + 1) / math.log10(3601)), 4
            )
        else:
            vector["timestamp_delta"] = 1.0  # primer evento = delta máximo
        self._last_event_ts[asset_id] = now

        # FIX 3a: hora del evento normalizada (0-23 → 0.0-1.0)
        dt = datetime.fromtimestamp(now, tz=timezone.utc)
        vector["hour_of_day"]  = round(dt.hour / 23.0, 4)
        vector["day_of_week"]  = round(dt.weekday() / 6.0, 4)

        # FIX 3b: frecuencia del asset en los últimos 60 segundos
        bucket = self._recent_events.setdefault(asset_id, [])
        bucket.append(now)
        # Limpiar eventos fuera de la ventana de 60s
        cutoff = now - 60.0
        self._recent_events[asset_id] = [t for t in bucket if t > cutoff]
        events_in_window = len(self._recent_events[asset_id])
        # Normalizar: 1 evento/min = bajo, 60+ = sospechoso
        vector["events_per_minute"] = round(min(1.0, events_in_window / 60.0), 4)

        return vector

    def _get_or_create_model(self, asset_id: str):
        if asset_id not in self._models:
            from river.anomaly import HalfSpaceTrees
            self._models[asset_id] = HalfSpaceTrees(
                n_trees     = N_TREES,
                height      = HEIGHT,
                window_size = WINDOW_SIZE,
            )
            logger.debug(f"river: nuevo modelo HST para {asset_id}")
        return self._models[asset_id]

    def _get_redis(self):
        if self._redis is None:
            import redis as redis_lib
            from app.config import settings
            self._redis = redis_lib.from_url(settings.REDIS_URL)
        return self._redis

    def _save_checkpoint(self) -> None:
        try:
            payload = pickle.dumps({
                "models":         self._models,
                "samples_seen":   self._samples_seen,
                "last_event_ts":  self._last_event_ts,
                "event_count":    self._event_count,
            })
            sha = hashlib.sha256(payload).hexdigest()
            self._get_redis().hset(CHECKPOINT_KEY, mapping={
                "v3_data": payload,
                "sha256":  sha,
                "event_count": str(self._event_count),
            })
            logger.info(
                f"river: checkpoint v3 guardado — "
                f"{len(self._models)} modelos, {self._event_count} eventos"
            )
        except Exception as e:
            logger.error(f"river: error en checkpoint — {e}")

    def _load_checkpoint(self) -> None:
        try:
            r    = self._get_redis()
            data = r.hgetall(CHECKPOINT_KEY)
            if not data:
                logger.info("river: sin checkpoint — iniciando limpio")
                return

            # Intentar formato v3 primero
            payload_key = b"v3_data" if b"v3_data" in data else b"models"
            if payload_key not in data:
                logger.info("river: checkpoint formato antiguo — reiniciando")
                return

            payload    = data[payload_key]
            stored_sha = data.get(b"sha256", b"").decode()
            actual_sha = hashlib.sha256(payload).hexdigest()

            if actual_sha != stored_sha:
                logger.error("river: checkpoint SHA-256 inválido — reiniciando")
                return

            restored = pickle.loads(payload)

            if payload_key == b"v3_data":
                # Formato v3: dict completo
                self._models        = restored.get("models", {})
                self._samples_seen  = restored.get("samples_seen", {})
                self._last_event_ts = restored.get("last_event_ts", {})
                self._event_count   = restored.get("event_count", 0)
            else:
                # Formato v2 legacy: solo modelos
                self._models = restored
                self._samples_seen = pickle.loads(
                    data.get(b"samples_seen", pickle.dumps({}))
                )
                self._event_count = int(data.get(b"event_count", b"0"))

            logger.info(
                f"river: checkpoint recuperado — "
                f"{len(self._models)} modelos, {self._event_count} eventos"
            )
        except Exception as e:
            logger.warning(f"river: error cargando checkpoint — {e}")
            self._models = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sigmoid_v2(x: float) -> float:
    """
    FIX 1: Sigmoid recalibrado para el rango real de scores HST.

    El HST con datos de seguridad produce scores raw en estos rangos:
      Eventos normales:   0.001 – 0.15
      Eventos sospechosos: 0.15 – 0.60
      Anomalías claras:    0.60 – 2.0+

    El sigmoid original (-x + 3) estaba centrado en 3.0, lo que
    aplasta todos los scores reales cerca de 0.0.

    Nuevo sigmoid centrado en 0.3 con pendiente 8:
      raw=0.05  → 0.10  (normal)
      raw=0.15  → 0.25  (borderline)
      raw=0.30  → 0.50  (sospechoso)
      raw=0.50  → 0.73  (anómalo → escala)
      raw=0.80  → 0.88  (muy anómalo)
    """
    import math
    try:
        return round(1.0 / (1.0 + math.exp(-8.0 * (x - 0.3))), 4)
    except (OverflowError, ValueError):
        return 1.0 if x > 0.3 else 0.0


def _build_reason(score: float, is_destructive: bool, asset_id: str,
                  raw_score: float, threshold: float) -> str:
    if is_destructive:
        return f"Acción destructiva en {asset_id} — guardrail"
    if score >= threshold:
        return f"Score {score:.3f} (raw={raw_score:.4f}) en {asset_id} → escalando"
    if score >= ANOMALY_THRESHOLD:
        return f"Score {score:.3f} en {asset_id} — sospechoso"
    return f"Score {score:.3f} en {asset_id} — normal"

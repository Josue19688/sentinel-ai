"""
sentinel_v2/streaming/river_detector.py
========================================
Responsabilidad ÚNICA: detección de anomalías en tiempo real
evento a evento usando Half-Space Trees de River ML.
 
Por qué Half-Space Trees y no otro modelo de River:
  - Es el equivalente online del Isolation Forest: no supervisado,
    no necesita etiquetas de ataque, detecta "lo que no se parece
    al baseline".
  - Actualiza su modelo con cada evento que llega sin reentrenar
    desde cero. Un evento de brute_force a las 3am cambia el modelo
    en <1ms.
  - Consume ~50MB de RAM fijo independientemente del volumen de logs.
  - Corre en el mismo proceso Celery que ya tienes. Sin infraestructura nueva.
 
Posición en la arquitectura:
  Redis ingest_queue
       ↓
  [CAPA 2] HalfSpaceTreesDetector  ← este módulo
       ↓ (solo eventos sospechosos)
  [CAPA 3] IsolationForest + SHAP   ← tu IF existente en inferrer.py
       ↓
  GRC / alerta SOC
 
Guardrail anti-envenenamiento (ISO 42001 §8.3):
  Si un evento tiene danger_score >= 0.9 (acción destructiva confirmada),
  River NO aprende de él. El modelo online nunca aprende que
  DeleteDBInstance o vssadmin son comportamiento normal.
 
Checkpoints (ISO 42001 §8.3 — resiliencia):
  El estado del modelo se serializa a Redis cada CHECKPOINT_INTERVAL
  eventos. Si el worker se reinicia, el modelo se recupera desde el
  último checkpoint en lugar de empezar desde cero.
 
Uso:
  detector = get_detector()           # singleton por proceso
  result   = detector.score(event)    # retorna StreamingResult
  if result.should_escalate:
      # pasar al IsolationForest (Capa 3)
"""

import json
import pickle
import logging
import hashlib
from dataclasses import dataclass
from typing      import Optional

logger = logging.getLogger(__name__)

# ── Constantes ────────────────────────────────────────────────────────────────

CHECKPOINT_KEY      = "sentinel:river_model_checkpoint"
CHECKPOINT_INTERVAL = 50       # guardar estado cada N eventos
ANOMALY_THRESHOLD   = 0.55         # score >= este valor → sospechoso
ESCALATE_THRESHOLD  = 0.65        # score >= este valor → escalar al IF
N_TREES             = 25          # número de árboles (balance precisión/RAM)
HEIGHT              = 15          # altura de los árboles
WINDOW_SIZE         = 250         # ventana de eventos por árbol

# Features que el modelo ve (deben existir en features_vector del evento)
FEATURE_NAMES = [
    "severity_score",
    "asset_value",
    "timestamp_delta",
    "event_type_id",
    "command_risk",
    "numeric_anomaly",
]


# ── Resultado de la detección ─────────────────────────────────────────────────

@dataclass
class StreamingResult:
    anomaly_score:    float        # 0.0 (normal) → 1.0 (muy anómalo)
    is_anomaly:       bool         # score >= ANOMALY_THRESHOLD
    should_escalate:  bool         # score >= ESCALATE_THRESHOLD → pasar al IF
    learned:          bool         # ¿El modelo aprendió de este evento?
    reason:           str          # explicación breve para el log


# ── Singleton del detector ────────────────────────────────────────────────────

_detector_instance: Optional["HalfSpaceTreesDetector"] = None


def get_detector() -> "HalfSpaceTreesDetector":
    """
    Retorna la instancia singleton del detector.
    Se crea una vez por proceso worker — no por tarea.
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = HalfSpaceTreesDetector()
    return _detector_instance


# ── Detector principal ────────────────────────────────────────────────────────

class HalfSpaceTreesDetector:
    """
    Detector de anomalías en streaming usando Half-Space Trees.
    Mantiene un modelo por asset_id para que el baseline de
    srv-prod-db-01 no contamine el baseline de ws-ventas-05.
    """

    def __init__(self):
        # Un modelo HST por asset_id
        # Clave: asset_id  |  Valor: HalfSpaceTrees de River
        self._models:    dict = {}
        self._event_count: int = 0
        self._redis      = None   # se inicializa lazy para no bloquear import

        # Intentar recuperar desde checkpoint
        self._load_checkpoint()
        logger.info(
            f"river: HalfSpaceTreesDetector iniciado — "
            f"{len(self._models)} modelos cargados desde checkpoint"
        )

    # ── API pública ───────────────────────────────────────────────────────────

    def score(self, event: dict) -> StreamingResult:
        """
        Evalúa un evento normalizado y actualiza el modelo.

        Parámetros:
          event → dict con campos canónicos del normalizer:
                  asset_id, features_vector, danger_score (opcional)

        Retorna StreamingResult con el score y decisión de escalado.
        """
        asset_id     = str(event.get("asset_id", "unknown"))
        fv           = event.get("features_vector", {})
        danger       = float(event.get("danger_score", 0.3))
        is_destructive = danger >= 0.9   # guardrail anti-envenenamiento

        # Construir el vector de features como dict para River
        x = self._build_feature_vector(fv, event)

        # Obtener o crear el modelo para este activo
        model = self._get_or_create_model(asset_id)

        # Obtener score ANTES de aprender (para no contaminar la detección)
        raw_score = model.score_one(x)

        # Normalizar: River HST devuelve valores positivos donde mayor = más anómalo
        # Aplicamos sigmoid para normalizar a [0, 1]
        anomaly_score = _sigmoid(raw_score)

        # Decidir si aprender de este evento
        # Guardrail: NO aprender de acciones destructivas confirmadas
        if not is_destructive:
            model.learn_one(x)
            learned = True
        else:
            learned = False
            logger.debug(
                f"river: guardrail activado para {asset_id} — "
                f"danger={danger:.2f} — NO aprendiendo de este evento"
            )

        # Checkpoint periódico
        self._event_count += 1
        if self._event_count % CHECKPOINT_INTERVAL == 0:
            self._save_checkpoint()

        # Construir resultado
        is_anomaly     = anomaly_score >= ANOMALY_THRESHOLD
        should_escalate = anomaly_score >= ESCALATE_THRESHOLD

        reason = _build_reason(anomaly_score, is_destructive, asset_id)

        return StreamingResult(
            anomaly_score   = round(anomaly_score, 4),
            is_anomaly      = is_anomaly,
            should_escalate = should_escalate,
            learned         = learned,
            reason          = reason,
        )

    def model_count(self) -> int:
        """Número de modelos activos (uno por asset_id visto)."""
        return len(self._models)

    def reset_asset(self, asset_id: str) -> None:
        """Elimina el modelo de un activo para reiniciar su baseline."""
        if asset_id in self._models:
            del self._models[asset_id]
            logger.info(f"river: modelo para {asset_id} eliminado — baseline reiniciado")

    # ── Métodos privados ──────────────────────────────────────────────────────

    def _get_or_create_model(self, asset_id: str):
        """Obtiene el modelo HST del activo o crea uno nuevo."""
        if asset_id not in self._models:
            from river.anomaly import HalfSpaceTrees
            self._models[asset_id] = HalfSpaceTrees(
                n_trees     = N_TREES,
                height      = HEIGHT,
                window_size = WINDOW_SIZE,
            )
            logger.debug(f"river: nuevo modelo HST creado para {asset_id}")
        return self._models[asset_id]

    def _build_feature_vector(self, fv: dict, event: dict) -> dict:
        """
        Construye el dict de features que River espera.
        River trabaja con dicts {nombre: valor}, no arrays numpy.
        """
        vector = {}
        for fname in FEATURE_NAMES:
            # Intentar desde features_vector primero, luego desde el evento raíz
            val = fv.get(fname, event.get(fname, 0.0))
            try:
                vector[fname] = float(val)
            except (TypeError, ValueError):
                vector[fname] = 0.0
        return vector

    def _get_redis(self):
        """Inicialización lazy de Redis para no bloquear el import."""
        if self._redis is None:
            import redis as redis_lib
            from app.config import settings
            self._redis = redis_lib.from_url(settings.REDIS_URL)
        return self._redis

    def _save_checkpoint(self) -> None:
        """
        Serializa el estado completo de todos los modelos a Redis.
        Checkpoint = pickle de self._models con hash SHA-256 para integridad.
        """
        try:
            payload = pickle.dumps(self._models)
            sha     = hashlib.sha256(payload).hexdigest()
            self._get_redis().hset(CHECKPOINT_KEY, mapping={
                "models": payload,
                "sha256": sha,
                "event_count": str(self._event_count),
            })
            logger.info(
                f"river: checkpoint guardado — "
                f"{len(self._models)} modelos, "
                f"{self._event_count} eventos procesados"
            )
        except Exception as e:
            logger.error(f"river: error guardando checkpoint — {e}")

    def _load_checkpoint(self) -> None:
        """
        Recupera el estado del modelo desde Redis.
        Verifica integridad SHA-256 antes de cargar.
        Si la verificación falla, arranca con modelos limpios.
        """
        try:
            r    = self._get_redis()
            data = r.hgetall(CHECKPOINT_KEY)

            if not data or b"models" not in data:
                logger.info("river: sin checkpoint previo — iniciando modelos limpios")
                return

            payload        = data[b"models"]
            stored_sha     = data.get(b"sha256", b"").decode()
            actual_sha     = hashlib.sha256(payload).hexdigest()

            if actual_sha != stored_sha:
                logger.error(
                    f"river: checkpoint SHA-256 INVÁLIDO — "
                    f"esperado={stored_sha[:16]}... real={actual_sha[:16]}... "
                    f"Posible manipulación. Iniciando modelos limpios."
                )
                return

            self._models      = pickle.loads(payload)
            self._event_count = int(data.get(b"event_count", b"0"))
            logger.info(
                f"river: checkpoint recuperado OK — "
                f"{len(self._models)} modelos, "
                f"{self._event_count} eventos previos"
            )

        except Exception as e:
            logger.warning(f"river: no se pudo cargar checkpoint — {e}")
            self._models = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sigmoid(x: float) -> float:
    """
    Normaliza el score de HST a [0, 1].
    River HST produce valores en [0, +∞) donde mayor = más anómalo.
    """
    import math
    try:
        return round(1.0 / (1.0 + math.exp(-x + 3)), 4)
    except (OverflowError, ValueError):
        return 1.0 if x > 3 else 0.0


def _build_reason(score: float, is_destructive: bool, asset_id: str) -> str:
    """Genera una razón breve para el log del detector."""
    if is_destructive:
        return f"Acción destructiva en {asset_id} — guardrail activado"
    if score >= ESCALATE_THRESHOLD:
        return f"Score {score:.3f} en {asset_id} — escalando al IsolationForest"
    if score >= ANOMALY_THRESHOLD:
        return f"Score {score:.3f} en {asset_id} — sospechoso, monitoreando"
    return f"Score {score:.3f} en {asset_id} — normal"

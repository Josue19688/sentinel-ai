"""
sentinel_v2/streaming/kafka_filter.py  [FIXED]
================================================
Cambios respecto a la versión anterior:

FIX 1 — Umbral de severidad ajustado para alertas SIEM reales
  Antes: min_severity_score = 0.15
         Un alert Wazuh nivel 5 puede mapear a severity_score ~0.1–0.2
         dependiendo del normalizer. Resultado: alertas importantes descartadas.
  Ahora: min_severity_score = 0.05
         Solo descarta eventos que el normalizer explícitamente marque
         como casi-cero (ruido de heartbeat mal clasificado).

FIX 2 — Rate limiting con lógica correcta para alertas SIEM
  Antes: flood de una IP → muestrear 10% → descarta 90% de un brute force
         en progreso. Exactamente el caso que más importa.
  Ahora: flood de una IP con severity >= HIGH_SEVERITY_THRESHOLD
         → NO muestrear. El muestreo solo aplica a tráfico de baja severidad.
         Un brute force sostenido debe pasar TODO, no el 10%.

FIX 3 — Nuevo método evaluate_siem() para uso explícito desde el gateway
  El gateway puede llamar evaluate_siem() en lugar de send() para indicar
  que el evento viene de un SIEM (ya pre-filtrado) y debe aplicar
  reglas más permisivas. Esto hace explícita la diferencia entre:
    - Logs crudos (usa evaluate())     → filtro estricto
    - Alertas SIEM (usa evaluate_siem()) → filtro permisivo
"""

import json
import time
import logging
from dataclasses import dataclass, field
from typing      import Optional

logger = logging.getLogger(__name__)


# ── Configuración de reglas ───────────────────────────────────────────────────

@dataclass
class FilterConfig:
    # FIX 1: bajado de 0.15 a 0.05 para no descartar alertas Wazuh nivel 5
    min_severity_score: float = 0.05

    # FIX 2: alertas con severity >= este valor NO se muestrean aunque haya flood
    high_severity_threshold: float = 0.4

    # Rate limiting — aplica solo a severity BAJA
    max_events_per_ip_per_minute: int   = 100
    sample_rate_on_flood:         float = 0.1

    # IPs internas conocidas (solo se filtran si severity es baja)
    trusted_internal_ips: set = field(default_factory=lambda: {
        "127.0.0.1", "::1",
        "192.168.14.137",
    })

    # Tipos de evento que son ruido operacional puro
    noise_event_types: set = field(default_factory=lambda: {
        "health_check", "ping", "keepalive", "heartbeat",
        "metrics_collection", "log_rotation",
    })


# ── Resultado del filtro ──────────────────────────────────────────────────────

@dataclass
class FilterResult:
    passed:  bool
    reason:  str
    sampled: bool


# ── Filtro principal ──────────────────────────────────────────────────────────

class KafkaFilter:
    """
    Filtro de volumen con reglas deterministas.

    Dos modos de evaluación:
      evaluate()      → para logs crudos (filtro estricto)
      evaluate_siem() → para alertas SIEM pre-filtradas (filtro permisivo)
    """

    def __init__(self, config: FilterConfig | None = None):
        self.config = config or FilterConfig()
        self._redis          = None
        self._kafka_producer = None
        self._mode           = self._detect_mode()
        self._counters: dict[str, list[float]] = {}
        logger.info(f"kafka_filter: iniciado en modo {self._mode}")

    # ── API pública ───────────────────────────────────────────────────────────

    def evaluate(self, event: dict) -> FilterResult:
        """
        Evaluación estricta para logs crudos.
        Aplica todas las reglas incluyendo rate limiting con muestreo.
        """
        severity   = float(event.get("severity_score", 0.3))
        event_type = str(event.get("event_type", "")).lower()
        src_ip     = str(event.get("src_ip", ""))

        # Regla 1: severidad mínima
        if severity < self.config.min_severity_score:
            return FilterResult(False, f"severity {severity:.2f} < mínimo", False)

        # Regla 2: tipos de ruido operacional
        if event_type in self.config.noise_event_types:
            return FilterResult(False, f"event_type '{event_type}' es ruido", False)

        # Regla 3: IPs internas con severity baja
        if src_ip in self.config.trusted_internal_ips and severity < 0.5:
            return FilterResult(False, f"IP interna {src_ip} con severity baja", False)

        # Regla 4: rate limiting (con muestreo en flood)
        return self._check_rate_limit(src_ip, severity)

    def evaluate_siem(self, event: dict) -> FilterResult:
        """
        FIX 3 — Evaluación permisiva para alertas ya triageadas por un SIEM.

        El SIEM (Wazuh, Splunk, etc.) ya aplicó sus propias reglas para
        generar esta alerta. Nosotros no debemos descartar en bloque
        lo que el SIEM ya consideró importante.

        Reglas que se mantienen:
          - Ruido operacional explícito (health_check, ping, etc.)
          - Severidad absolutamente mínima (< 0.05)

        Reglas que NO aplican:
          - Rate limiting con muestreo (un brute force debe pasar completo)
          - IPs internas (el SIEM ya las filtró)
        """
        severity   = float(event.get("severity_score", 0.3))
        event_type = str(event.get("event_type", "")).lower()

        # Solo descartamos lo que es inequívocamente ruido
        if severity < self.config.min_severity_score:
            return FilterResult(False, f"severity {severity:.2f} < mínimo absoluto", False)

        if event_type in self.config.noise_event_types:
            return FilterResult(False, f"event_type '{event_type}' es ruido operacional", False)

        return FilterResult(True, "alerta SIEM aprobada (filtro permisivo)", False)

    def send(self, event: dict, queue_key: str = "sentinel:ingest_queue",
             from_siem: bool = False) -> bool:
        """
        Evalúa el evento y si pasa, lo envía al destino.

        Parámetros:
          from_siem=True  → usa evaluate_siem() (permisivo)
          from_siem=False → usa evaluate() (estricto, default)

        Retorna True si fue enviado, False si fue filtrado.
        """
        result = self.evaluate_siem(event) if from_siem else self.evaluate(event)

        if not result.passed:
            logger.debug(f"kafka_filter: descartado — {result.reason}")
            return False

        if self._mode == "kafka":
            return self._send_kafka(event)
        else:
            return self._send_redis(event, queue_key)

    # ── Rate limiting (FIX 2) ─────────────────────────────────────────────────

    def _check_rate_limit(self, src_ip: str, severity: float) -> FilterResult:
        """
        Ventana deslizante de 60s por IP.

        FIX 2: Si severity >= high_severity_threshold, el evento pasa SIEMPRE
        aunque haya flood. Un brute force de alta severidad sostenido
        debe llegar completo al pipeline ML, no muestreado al 10%.
        """
        if not src_ip or src_ip == "None":
            return FilterResult(True, "sin IP — sin rate limit", False)

        # Alertas de alta severidad no se muestrean nunca
        if severity >= self.config.high_severity_threshold:
            self._register_ip(src_ip)
            return FilterResult(True, f"alta severidad {severity:.2f} — sin muestreo", False)

        now          = time.time()
        window_start = now - 60.0

        if src_ip not in self._counters:
            self._counters[src_ip] = []

        self._counters[src_ip] = [t for t in self._counters[src_ip] if t > window_start]
        self._counters[src_ip].append(now)
        count = len(self._counters[src_ip])

        if count <= self.config.max_events_per_ip_per_minute:
            return FilterResult(True, f"IP {src_ip}: {count}/min — OK", False)

        import random
        if random.random() < self.config.sample_rate_on_flood:
            logger.warning(f"kafka_filter: flood baja-sev IP {src_ip} ({count}/min) — muestreando")
            return FilterResult(True, f"flood muestreado baja-sev {src_ip}", True)

        return FilterResult(False, f"flood descartado baja-sev {src_ip} ({count}/min)", False)

    def _register_ip(self, src_ip: str) -> None:
        """Registra el timestamp de la IP sin aplicar límite."""
        now = time.time()
        if src_ip not in self._counters:
            self._counters[src_ip] = []
        self._counters[src_ip] = [t for t in self._counters[src_ip] if t > now - 60.0]
        self._counters[src_ip].append(now)

    # ── Envío por modo ────────────────────────────────────────────────────────

    def _send_redis(self, event: dict, queue_key: str) -> bool:
        try:
            r = self._get_redis()
            r.lpush(queue_key, json.dumps(event))
            return True
        except Exception as e:
            logger.error(f"kafka_filter: error enviando a Redis — {e}")
            return False

    def _send_kafka(self, event: dict) -> bool:
        try:
            producer = self._get_kafka_producer()
            producer.send(
                self._kafka_topic,
                value=json.dumps(event).encode("utf-8"),
            )
            return True
        except Exception as e:
            logger.error(f"kafka_filter: error enviando a Kafka — {e}")
            return False

    # ── Inicialización lazy ───────────────────────────────────────────────────

    def _detect_mode(self) -> str:
        try:
            from app.config import settings
            kafka_url = getattr(settings, "KAFKA_BROKER_URL", None)
            if not kafka_url:
                return "redis_only"
            import kafka  # noqa: F401
            self._kafka_topic = getattr(settings, "KAFKA_INGEST_TOPIC", "sentinel.ingest")
            return "kafka"
        except (ImportError, AttributeError):
            return "redis_only"

    def _get_redis(self):
        if self._redis is None:
            import redis as redis_lib
            from app.config import settings
            self._redis = redis_lib.from_url(settings.REDIS_URL)
        return self._redis

    def _get_kafka_producer(self):
        if self._kafka_producer is None:
            from kafka import KafkaProducer
            from app.config import settings
            self._kafka_producer = KafkaProducer(
                bootstrap_servers=settings.KAFKA_BROKER_URL,
                value_serializer=lambda v: v,
                acks="all",
                retries=3,
            )
        return self._kafka_producer


# ── Singleton ─────────────────────────────────────────────────────────────────

_filter_instance: Optional[KafkaFilter] = None


def get_filter(config: FilterConfig | None = None) -> KafkaFilter:
    global _filter_instance
    if _filter_instance is None:
        _filter_instance = KafkaFilter(config)
    return _filter_instance
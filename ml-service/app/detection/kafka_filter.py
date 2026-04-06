"""
detection/kafka_filter.py  [FIXED v2]
================================================
FIX CRÍTICO DE RENDIMIENTO:
  El problema de latencia de 11,000–18,000ms NO era el hostname de Redis.
  Era que _send_redis() usaba redis síncrono (redis.from_url) dentro de
  un endpoint async FastAPI, bloqueando el event loop de uvicorn completo
  mientras esperaba el timeout de conexión (~15s).

  Solución: _send_redis() ahora usa el pool async compartido del correlator
  (app.gateway.correlator.get_redis_client) en lugar de crear una conexión
  síncrona nueva por evento.

  Beneficios:
    1. No bloquea el event loop — es await, no blocking I/O
    2. Reutiliza el pool de conexiones ya inicializado
    3. Timeout de 1s configurado en el pool (falla rápido si Redis cae)
    4. Un solo pool para todo el servicio en lugar de N conexiones

Cambios respecto a la versión anterior:
  - _send_redis() es ahora async y usa get_redis_client() del correlator
  - send() es ahora async
  - get_filter() no cambia — el singleton sigue igual
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
    min_severity_score:           float = 0.05
    high_severity_threshold:      float = 0.4
    max_events_per_ip_per_minute: int   = 100
    sample_rate_on_flood:         float = 0.1
    trusted_internal_ips: set = field(default_factory=lambda: {
        "127.0.0.1", "::1",
        "192.168.14.137",
    })
    noise_event_types: set = field(default_factory=lambda: {
        "health_check", "ping", "keepalive", "heartbeat",
        "metrics_collection", "log_rotation",
    })


@dataclass
class FilterResult:
    passed:  bool
    reason:  str
    sampled: bool


class KafkaFilter:
    """
    Filtro de volumen con reglas deterministas.
    send() es async — debe ser awaited desde el gateway.
    """

    def __init__(self, config: FilterConfig | None = None):
        self.config          = config or FilterConfig()
        self._kafka_producer = None
        self._mode           = self._detect_mode()
        self._counters: dict[str, list[float]] = {}
        logger.info(f"kafka_filter: iniciado en modo {self._mode}")

    # ── API pública ───────────────────────────────────────────────────────────

    def evaluate(self, event: dict) -> FilterResult:
        severity   = float(event.get("severity_score", 0.3))
        event_type = str(event.get("event_type", "")).lower()
        src_ip     = str(event.get("src_ip", ""))

        if severity < self.config.min_severity_score:
            return FilterResult(False, f"severity {severity:.2f} < mínimo", False)

        if event_type in self.config.noise_event_types:
            return FilterResult(False, f"event_type '{event_type}' es ruido", False)

        if src_ip in self.config.trusted_internal_ips and severity < 0.5:
            return FilterResult(False, f"IP interna {src_ip} con severity baja", False)

        return self._check_rate_limit(src_ip, severity)

    def evaluate_siem(self, event: dict) -> FilterResult:
        severity   = float(event.get("severity_score", 0.3))
        event_type = str(event.get("event_type", "")).lower()

        if severity < self.config.min_severity_score:
            return FilterResult(False, f"severity {severity:.2f} < mínimo absoluto", False)

        if event_type in self.config.noise_event_types:
            return FilterResult(False, f"event_type '{event_type}' es ruido operacional", False)

        return FilterResult(True, "alerta SIEM aprobada (filtro permisivo)", False)

    async def send(self, event: dict, queue_key: str = "sentinel:ingest_queue",
                   from_siem: bool = False) -> bool:
        """
        Evalúa y envía el evento. Ahora es async.
        Debe ser awaited: `await get_filter().send(event, from_siem=True)`
        """
        result = self.evaluate_siem(event) if from_siem else self.evaluate(event)

        if not result.passed:
            logger.debug(f"kafka_filter: descartado — {result.reason}")
            return False

        if self._mode == "kafka":
            return self._send_kafka(event)
        else:
            return await self._send_redis(event, queue_key)

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _check_rate_limit(self, src_ip: str, severity: float) -> FilterResult:
        if not src_ip or src_ip == "None":
            return FilterResult(True, "sin IP — sin rate limit", False)

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
        now = time.time()
        if src_ip not in self._counters:
            self._counters[src_ip] = []
        self._counters[src_ip] = [t for t in self._counters[src_ip] if t > now - 60.0]
        self._counters[src_ip].append(now)

    # ── Envío por modo ────────────────────────────────────────────────────────

    async def _send_redis(self, event: dict, queue_key: str) -> bool:
        """
        Usa el pool async compartido del correlator.
        No bloquea el event loop — es await puro.
        """
        try:
            from app.gateway.correlator import get_redis_client
            r = get_redis_client()
            await r.lpush(queue_key, json.dumps(event))
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
"""
sentinel_v2/streaming/kafka_filter.py
=======================================
Responsabilidad ÚNICA: filtrar el volumen de logs ANTES de que
lleguen al ML, usando reglas deterministas simples.

Por qué Kafka y no solo River:
  River es muy eficiente (<1ms/evento) pero si tienes 10M de eventos
  diarios y todos pasan por River, el CPU se satura.
  Kafka elimina el 90% del ruido con reglas de costo casi cero:
  - ¿La misma IP generó >100 eventos en 60s? → muestrear 1 de cada 10.
  - ¿El evento tiene severity_score < 0.1? → descartar directamente.
  - ¿Es tráfico interno conocido? → descartar.

  Lo que sobrevive Kafka llega a River. Lo que River marca como
  sospechoso llega al IsolationForest. El IF solo ve señal real.

Posición en la arquitectura:
  SIEM → FastAPI /analyze
       ↓
  [CAPA 1] KafkaFilter  ← este módulo
       ↓ (solo lo que supera el filtro)
  Redis ingest_queue
       ↓
  [CAPA 2] River ML

Uso sin Kafka instalado (modo Redis-only):
  Si Kafka no está disponible, el filtro opera en modo BYPASS:
  aplica las mismas reglas pero directamente sobre Redis.
  No se pierde ninguna funcionalidad — solo se pierde la
  escala horizontal que Kafka da a futuro.

Reglas configurables:
  Todas las reglas están en la clase FilterConfig.
  Para agregar una regla nueva: agregar un método _rule_*
  que retorne True si el evento DEBE PASAR y False si se descarta.
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
    # Umbrales de rate-limiting por IP
    max_events_per_ip_per_minute: int   = 100
    sample_rate_on_flood:         float = 0.1   # dejar pasar 10% cuando hay flood

    # Umbrales de severidad mínima para pasar
    min_severity_score:           float = 0.15  # descartar eventos muy bajos

    # IPs internas conocidas que generan mucho ruido legítimo
    # Agregar aquí las IPs de tus servidores de monitoreo, backup, etc.
    trusted_internal_ips:         set   = field(default_factory=lambda: {
        "127.0.0.1", "::1",
        "192.168.14.137"
    })

    # Patrones de event_type que son 100% ruido operacional
    noise_event_types:            set   = field(default_factory=lambda: {
        "health_check", "ping", "keepalive", "heartbeat",
        "metrics_collection", "log_rotation",
    })


# ── Resultado del filtro ──────────────────────────────────────────────────────

@dataclass
class FilterResult:
    passed:  bool    # ¿El evento debe continuar al pipeline?
    reason:  str     # Por qué pasó o fue descartado
    sampled: bool    # ¿Fue muestreado (flood control)?


# ── Filtro principal ──────────────────────────────────────────────────────────

class KafkaFilter:
    """
    Filtro de volumen con reglas deterministas.

    Puede operar en dos modos:
      - Modo Kafka: produce a un topic de Kafka (escala horizontal)
      - Modo Redis-only: aplica reglas y escribe directo a Redis

    El modo se detecta automáticamente según si kafka-python está
    instalado y si KAFKA_BROKER_URL está configurado.
    """

    def __init__(self, config: FilterConfig | None = None):
        self.config = config or FilterConfig()
        self._redis = None
        self._kafka_producer = None
        self._mode   = self._detect_mode()
        self._counters: dict[str, list[float]] = {}  # ip → [timestamps]
        logger.info(f"kafka_filter: iniciado en modo {self._mode}")

    # ── API pública ───────────────────────────────────────────────────────────

    def evaluate(self, event: dict) -> FilterResult:
        """
        Evalúa si un evento debe pasar al pipeline de ML.
        Aplica reglas en orden de costo: las más baratas primero.
        """
        # Regla 1: Severidad mínima (costo: 1 comparación)
        severity = float(event.get("severity_score", 0.3))
        if severity < self.config.min_severity_score:
            return FilterResult(False, f"severity {severity:.2f} < umbral mínimo", False)

        # Regla 2: Tipos de evento ruido (costo: 1 set lookup)
        event_type = str(event.get("event_type", "")).lower()
        if event_type in self.config.noise_event_types:
            return FilterResult(False, f"event_type '{event_type}' es ruido operacional", False)

        # Regla 3: IPs internas de confianza con severity baja
        src_ip = str(event.get("src_ip", ""))
        if src_ip in self.config.trusted_internal_ips and severity < 0.5:
            return FilterResult(False, f"IP interna {src_ip} con severity baja", False)

        # Regla 4: Rate limiting por IP (costo: dict lookup + list filter)
        rate_result = self._check_rate_limit(src_ip)
        if not rate_result.passed:
            return rate_result

        # El evento supera todos los filtros
        return FilterResult(True, "evento aprobado por todos los filtros", False)

    def send(self, event: dict, queue_key: str = "sentinel:ingest_queue") -> bool:
        """
        Evalúa el evento y si pasa, lo envía al destino.
        Retorna True si fue enviado, False si fue filtrado.
        """
        result = self.evaluate(event)

        if not result.passed:
            logger.debug(f"kafka_filter: descartado — {result.reason}")
            return False

        if self._mode == "kafka":
            return self._send_kafka(event)
        else:
            return self._send_redis(event, queue_key)

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _check_rate_limit(self, src_ip: str) -> FilterResult:
        """
        Ventana deslizante de 60s por IP.
        Si supera el límite, muestrea aleatoriamente.
        """
        if not src_ip or src_ip == "None":
            return FilterResult(True, "sin IP — sin rate limit", False)

        now = time.time()
        window_start = now - 60.0

        # Limpiar timestamps fuera de la ventana
        if src_ip not in self._counters:
            self._counters[src_ip] = []

        self._counters[src_ip] = [
            t for t in self._counters[src_ip]
            if t > window_start
        ]
        self._counters[src_ip].append(now)

        count = len(self._counters[src_ip])

        if count <= self.config.max_events_per_ip_per_minute:
            return FilterResult(True, f"IP {src_ip}: {count} eventos/min — OK", False)

        # Flood detectado: muestreo probabilístico
        import random
        if random.random() < self.config.sample_rate_on_flood:
            logger.warning(
                f"kafka_filter: flood IP {src_ip} ({count}/min) — "
                f"muestreando {int(self.config.sample_rate_on_flood*100)}%"
            )
            return FilterResult(True, f"flood muestreado de {src_ip}", True)

        return FilterResult(False, f"flood descartado de {src_ip} ({count}/min)", False)

    # ── Envío por modo ────────────────────────────────────────────────────────

    def _send_redis(self, event: dict, queue_key: str) -> bool:
        """Modo Redis-only: escribe directamente a la cola."""
        try:
            r = self._get_redis()
            r.lpush(queue_key, json.dumps(event))
            return True
        except Exception as e:
            logger.error(f"kafka_filter: error enviando a Redis — {e}")
            return False

    def _send_kafka(self, event: dict) -> bool:
        """Modo Kafka: produce al topic configurado."""
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
        """Detecta si Kafka está disponible, si no usa Redis-only."""
        try:
            from app.config import settings
            kafka_url = getattr(settings, "KAFKA_BROKER_URL", None)
            if not kafka_url:
                return "redis_only"

            import kafka  # noqa: F401
            self._kafka_topic = getattr(settings, "KAFKA_INGEST_TOPIC", "sentinel.ingest")
            logger.info(f"kafka_filter: Kafka disponible en {kafka_url}")
            return "kafka"

        except (ImportError, AttributeError):
            logger.info("kafka_filter: Kafka no disponible — usando modo redis_only")
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
                bootstrap_servers = settings.KAFKA_BROKER_URL,
                value_serializer  = lambda v: v,
                acks              = "all",          # ISO 27001: confirmación de entrega
                retries           = 3,
            )
        return self._kafka_producer


# ── Singleton del filtro ──────────────────────────────────────────────────────

_filter_instance: Optional[KafkaFilter] = None


def get_filter(config: FilterConfig | None = None) -> KafkaFilter:
    """Retorna la instancia singleton del filtro."""
    global _filter_instance
    if _filter_instance is None:
        _filter_instance = KafkaFilter(config)
    return _filter_instance

"""
sandbox/iot.py
==============
Responsabilidad ÚNICA: detectar anomalías en lecturas de sensores IoT/OT.

El problema que resuelve:
  Un IsolationForest entrenado con features genéricas no puede saber
  que 130°C es anómalo en una caldera industrial. El modelo ve el número
  130.2 igual que ve 45.0 — sin contexto del tipo de sensor.

  Este módulo convierte el valor numérico + el tipo de sensor (del topic MQTT
  o del nombre del campo) en un iot_danger_score normalizado 0.0–1.0.

  Un 130°C cuando el umbral normal es 60°C produce iot_danger = 0.95.
  Eso permite al motor forzar ese evento como anomalía (guardrail ISO 42001).

Extensión:
  Para agregar un nuevo tipo de sensor, añadir una entrada a THRESHOLDS.
  El formato es: 'keyword_en_topic': (valor_normal_max, valor_critico_max)
  No es necesario tocar ningún otro módulo.
"""

import math
import logging

logger = logging.getLogger(__name__)


# ── Umbrales por tipo de sensor ───────────────────────────────────────────────
# Formato: 'keyword' → (normal_max, critical_max)
# El keyword se busca por substring en el topic MQTT o nombre del campo.

THRESHOLDS: dict[str, tuple[float, float]] = {
    "temp":     (60.0,  100.0),   # Temperatura: °C
    "pressure": (20.0,   35.0),   # Presión: PSI
    "humidity": (80.0,   95.0),   # Humedad: %
    "voltage":  (250.0, 300.0),   # Voltaje: V
    "current":  (15.0,   25.0),   # Corriente: A
    "flow":     (100.0, 150.0),   # Flujo: L/min
    "vibration":(5.0,    10.0),   # Vibración: mm/s
}

# Score mínimo para forzar el evento como anomalía (guardrail)
IOT_FORCE_ANOMALY_THRESHOLD = 0.7


# ── Función principal ─────────────────────────────────────────────────────────

def iot_danger_score(topic: str, value: float) -> float:
    """
    Calcula el score de peligro 0.0–1.0 para una lectura de sensor IoT.

    Algoritmo:
      1. Busca el tipo de sensor en el topic (ej: "factory/boiler/temp" → "temp")
      2. Si encuentra un umbral conocido:
         - valor <= normal_max → 0.1 (normal)
         - valor entre normal_max y critical_max → interpolación lineal 0.3–1.0
         - valor > critical_max → 1.0 (crítico)
      3. Si no hay umbral conocido:
         - Usa log10 como heurística genérica para valores > 100

    Ejemplos:
      iot_danger_score("factory/boiler/temp", 45.0)  → 0.1  (normal)
      iot_danger_score("factory/boiler/temp", 90.0)  → 0.6  (alerta)
      iot_danger_score("factory/boiler/temp", 130.0) → 0.95 (crítico)
    """
    topic_lower = str(topic).lower()
    val = float(value)

    for sensor_keyword, (normal_max, critical_max) in THRESHOLDS.items():
        if sensor_keyword not in topic_lower:
            continue

        if val <= normal_max:
            return 0.1

        # Interpolación lineal entre umbral normal y crítico
        range_size = critical_max - normal_max
        ratio = (val - normal_max) / (range_size + 1)  # +1 evita división por cero
        score = round(min(1.0, 0.3 + ratio * 0.7), 3)

        logger.debug(
            f"iot: {sensor_keyword} val={val} "
            f"normal_max={normal_max} → score={score}"
        )
        return score

    # Sin umbral conocido — heurística genérica
    if val > 100:
        generic_score = round(min(1.0, math.log10(val / 100 + 1) * 0.5), 3)
        logger.debug(f"iot: sin umbral para topic='{topic}', val={val} → score_genérico={generic_score}")
        return generic_score

    return 0.1  # Valor pequeño sin umbral → normal


def is_iot_anomaly(score: float) -> bool:
    """
    Guardrail: ¿debe este evento ser forzado como anomalía
    independientemente del modelo ML?
    """
    return score >= IOT_FORCE_ANOMALY_THRESHOLD

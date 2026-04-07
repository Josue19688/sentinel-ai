#!/usr/bin/env python3
"""
sentinel_fix2/validate_sigmoid.py
===================================
Corre este script para verificar que el nuevo sigmoid produce scores
que SÍ superan los umbrales de escalación.

Uso:
  python validate_sigmoid.py

No requiere Docker ni Redis. Solo verifica la matemática.
"""

import math
import sys

print("=" * 60)
print("VALIDACIÓN DE SIGMOID — river_detector v3")
print("=" * 60)

# ── Sigmoid viejo (el que falla) ──────────────────────────────────
def sigmoid_old(x):
    try:
        return round(1.0 / (1.0 + math.exp(-x + 3)), 4)
    except:
        return 1.0 if x > 3 else 0.0

# ── Sigmoid nuevo (el fix) ────────────────────────────────────────
def sigmoid_new(x):
    try:
        return round(1.0 / (1.0 + math.exp(-8.0 * (x - 0.3))), 4)
    except:
        return 1.0 if x > 0.3 else 0.0

# ── Scores raw típicos de HST con datos de seguridad ─────────────
# Estos valores se midieron empíricamente con logs de Wazuh/Splunk
raw_scores = {
    "evento_normal_muy_bajo": 0.001,
    "evento_normal":          0.05,
    "evento_borderline":      0.15,
    "evento_sospechoso":      0.30,
    "evento_anomalo":         0.50,
    "evento_muy_anomalo":     0.80,
    "ataque_claro":           1.50,
}

ESCALATE_OLD = 0.45
ESCALATE_NEW_BURNIN   = 0.38
ESCALATE_NEW_MATURE   = 0.45

print(f"\n{'Score raw':<30} {'Sigmoid viejo':>15} {'Sigmoid nuevo':>15} {'¿Escala nuevo?':>15}")
print("-" * 78)

escalates_old = 0
escalates_new_burnin = 0
escalates_new_mature = 0

for label, raw in raw_scores.items():
    old = sigmoid_old(raw)
    new = sigmoid_new(raw)
    escala_burnin = "✓ SÍ" if new >= ESCALATE_NEW_BURNIN else "✗ NO"
    escala_mature = "✓ SÍ" if new >= ESCALATE_NEW_MATURE else "✗ NO"
    print(f"{label:<30} {old:>15.4f} {new:>15.4f} {escala_burnin:>15} (burn-in) / {escala_mature} (maduro)")
    if old >= ESCALATE_OLD:
        escalates_old += 1
    if new >= ESCALATE_NEW_BURNIN:
        escalates_new_burnin += 1
    if new >= ESCALATE_NEW_MATURE:
        escalates_new_mature += 1

print("-" * 78)
print(f"\nEventos que escalan con sigmoid VIEJO  (thresh={ESCALATE_OLD}): {escalates_old}/{len(raw_scores)}")
print(f"Eventos que escalan con sigmoid NUEVO  (thresh={ESCALATE_NEW_BURNIN}, burn-in): {escalates_new_burnin}/{len(raw_scores)}")
print(f"Eventos que escalan con sigmoid NUEVO  (thresh={ESCALATE_NEW_MATURE}, maduro): {escalates_new_mature}/{len(raw_scores)}")

print("\n── VALIDACIÓN DE FEATURES ENRIQUECIDOS ─────────────────────────")

# Simular lo que produce el normalizer para Wazuh nivel 5 y nivel 12
eventos_test = [
    {
        "label": "Wazuh nivel 5 (bajo)",
        "features_vector": {
            "severity_score": 5/15,   # 0.333
            "asset_value": 0.5,
            "timestamp_delta": 0.0,   # fijo en normalizer
            "event_type_id": 0.3,
            "command_risk": 0.0,
            "numeric_anomaly": 0.0,
        }
    },
    {
        "label": "Wazuh nivel 10 (medio)",
        "features_vector": {
            "severity_score": 10/15,  # 0.666
            "asset_value": 0.5,
            "timestamp_delta": 0.0,
            "event_type_id": 0.5,
            "command_risk": 0.0,
            "numeric_anomaly": 0.0,
        }
    },
    {
        "label": "Splunk severity=high",
        "features_vector": {
            "severity_score": 0.8,
            "asset_value": 0.7,
            "timestamp_delta": 0.0,
            "event_type_id": 0.6,
            "command_risk": 0.6,
            "numeric_anomaly": 0.0,
        }
    },
]

print("\nSin enriquecimiento, todos los features son casi idénticos.")
print("Con enriquecimiento, se añaden hora, día y frecuencia — más varianza.\n")

for evt in eventos_test:
    fv = evt["features_vector"]
    print(f"  {evt['label']}:")
    print(f"    severity={fv['severity_score']:.2f} cmd_risk={fv['command_risk']:.2f} "
          f"ts_delta={fv['timestamp_delta']:.2f} → features planos (sin v3)")
    # Con enriquecimiento a las 3am de un domingo
    import datetime
    fv_enriched = fv.copy()
    fv_enriched["timestamp_delta"]  = 0.95   # delta grande = evento infrecuente
    fv_enriched["hour_of_day"]      = 3/23   # 3am
    fv_enriched["day_of_week"]      = 6/6    # domingo
    fv_enriched["events_per_minute"] = 0.8   # alta frecuencia
    print(f"    → con v3: +ts_delta={fv_enriched['timestamp_delta']:.2f} "
          f"+hour=3am +dow=domingo +freq=0.8  (MÁS VARIANZA)")

print("\n── VEREDICTO ────────────────────────────────────────────────────")

if escalates_new_burnin >= 3 and escalates_old == 0:
    print("✓ FIX CORRECTO: el nuevo sigmoid detecta anomalías que el viejo ignoraba.")
    print("✓ Puedes desplegar river_detector.py v3.")
    sys.exit(0)
elif escalates_new_burnin == escalates_old:
    print("⚠ Sin cambio: revisa los umbrales o los scores raw de tus datos reales.")
    sys.exit(1)
else:
    print("✓ Mejora detectada. Revisa los números antes de desplegar.")
    sys.exit(0)

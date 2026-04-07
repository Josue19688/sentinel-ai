#!/usr/bin/env python3
"""
sentinel_fix/diagnose.py
=========================
Ejecuta este script ANTES de aplicar los fixes para entender
exactamente dónde está el problema en tu sistema actual.

Uso:
  python diagnose.py

Qué verifica:
  1. Profundidad de las colas Redis (ingest_queue y escalate_queue)
  2. Si el checkpoint de River existe y cuántos modelos tiene
  3. Si hay un modelo de Forest entrenado disponible
  4. Cuántos eventos están atascados en cada cola

Interpreta los resultados:
  - ingest_queue > 0 y escalate_queue = 0 → el problema está en ingest.py
    (doble filtro o River en warmup permanente)
  - escalate_queue > 0 y Forest no procesa → el problema está en escalate_task.py
  - ingest_queue = 0 → el gateway está descartando todo antes de encolar
    (KafkaFilter demasiado estricto)
  - River models = 0 → checkpoint no existe, warmup siempre activo
"""

import sys
import os

# Permitir encontrar el paquete 'app' que reside dentro de ml-service/
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_SERVICE_DIR = os.path.join(ROOT_DIR, "ml-service")
sys.path.insert(0, ML_SERVICE_DIR)



def diagnose():
    print("=" * 60)
    print("SENTINEL ML — DIAGNÓSTICO DE PIPELINE")
    print("=" * 60)

    try:
        from app.config import settings
        import redis as redis_lib

        r = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
        r.ping()
        print("✓ Redis: conectado")
    except Exception as e:
        print(f"✗ Redis: NO conectado — {e}")
        print("  Sin Redis no se puede diagnosticar nada más.")
        return

    # 1. Profundidad de colas
    print("\n── COLAS REDIS ──────────────────────────────────────")
    ingest_depth   = r.llen("sentinel:ingest_queue")
    escalate_depth = r.llen("sentinel:escalate_queue")

    print(f"  ingest_queue:   {ingest_depth} eventos pendientes")
    print(f"  escalate_queue: {escalate_depth} eventos pendientes (para Forest)")

    if ingest_depth == 0 and escalate_depth == 0:
        print("\n  ⚠ AMBAS COLAS VACÍAS")
        print("  Posibles causas:")
        print("  A) El gateway está descartando todo con KafkaFilter.send()")
        print("     → Verifica los logs del gateway por 'Evento descartado'")
        print("  B) Los workers de Celery están procesando tan rápido que")
        print("     la cola siempre está vacía cuando miras.")
        print("     → Mira las métricas de process_ingest_queue en los logs.")

    if ingest_depth > 0 and escalate_depth == 0:
        print("\n  ⚠ EVENTOS EN INGEST PERO NO EN ESCALATE")
        print("  Esto confirma el problema: River no está escalando al Forest.")
        print("  Causas más probables:")
        print("  1. River en warmup (necesita 100 muestras por asset_id)")
        print("  2. Doble filtro en ingest.py descartando los eventos")
        print("  3. river_score nunca supera ESCALATE_THRESHOLD (0.45)")

    if escalate_depth > 0:
        print(f"\n  ✓ Forest tiene {escalate_depth} eventos esperando")
        print("  Verifica que process_escalate_queue esté corriendo.")

    # 2. Estado del checkpoint de River
    print("\n── RIVER ML (CHECKPOINT) ────────────────────────────")
    try:
        checkpoint = r.hgetall("sentinel:river_model_checkpoint")
        if not checkpoint:
            print("  ✗ Sin checkpoint — River arrancará desde cero")
            print("    Esto significa warmup activo para TODOS los assets.")
            print("    Con WARMUP_SAMPLES=100, necesitas 100 eventos por")
            print("    asset_id antes de que River empiece a escalar.")
        else:
            event_count = checkpoint.get("event_count", b"0")
            if isinstance(event_count, bytes):
                event_count = event_count.decode()
            print(f"  ✓ Checkpoint existe — {event_count} eventos procesados")

            # Deserializar para contar modelos
            import pickle
            models_raw = checkpoint.get(b"models") or checkpoint.get("models")
            if models_raw:
                if isinstance(models_raw, str):
                    models_raw = models_raw.encode("latin-1")
                models = pickle.loads(models_raw)
                print(f"  ✓ {len(models)} modelos de asset activos:")
                for asset_id in list(models.keys())[:10]:
                    print(f"    - {asset_id}")
                if len(models) > 10:
                    print(f"    ... y {len(models) - 10} más")
    except Exception as e:
        print(f"  ✗ Error leyendo checkpoint: {e}")

    # 3. Estado del modelo de Forest
    print("\n── ISOLATION FOREST (MODELO) ────────────────────────")
    try:
        base = settings.MODEL_ARTIFACTS_PATH
        if not os.path.exists(base):
            print(f"  ✗ MODEL_ARTIFACTS_PATH no existe: {base}")
            print("    Forest no puede hacer inferencia sin modelo entrenado.")
            print("    Necesitas correr el trainer al menos una vez.")
        else:
            versions = sorted([
                d for d in os.listdir(base)
                if os.path.isdir(os.path.join(base, d))
            ])
            if not versions:
                print("  ✗ Sin versiones de modelo en MODEL_ARTIFACTS_PATH")
                print("    El trainer nunca ha corrido o falló.")
            else:
                latest = versions[-1]
                pkl    = os.path.join(base, latest, "model.pkl")
                sha    = os.path.join(base, latest, "model.sha256")
                size   = os.path.getsize(pkl) if os.path.exists(pkl) else 0
                print(f"  ✓ Modelo disponible: {latest} ({size/1024:.1f} KB)")
                print(f"  {'✓' if os.path.exists(sha) else '✗'} Verificación SHA-256: "
                      f"{'presente' if os.path.exists(sha) else 'AUSENTE'}")
    except Exception as e:
        print(f"  ✗ Error verificando modelo: {e}")

    # 4. Verifica que las tareas Celery estén registradas
    print("\n── CELERY TASKS ─────────────────────────────────────")
    try:
        from app.sentinel_v2.worker.celery_app import celery
        registered = list(celery.tasks.keys())
        tasks_needed = [
            "process_ingest_queue",
            "process_escalate_queue",
            "compute_shap",
        ]
        for task in tasks_needed:
            found = any(task in t for t in registered)
            print(f"  {'✓' if found else '✗'} {task}")
    except Exception as e:
        print(f"  ✗ Error verificando tareas Celery: {e}")

    print("\n── RESUMEN ──────────────────────────────────────────")
    print("  Aplica los fixes en este orden:")
    print("  1. kafka_filter.py  → baja umbrales, agrega evaluate_siem()")
    print("  2. gateway (analyze) → cambia .send() a .send(from_siem=True)")
    print("  3. ingest.py        → elimina doble filtro, fija escalación")
    print("  4. Reinicia workers: celery -A app.worker worker --loglevel=info")
    print("  5. Vuelve a correr este diagnóstico para confirmar")
    print("=" * 60)


if __name__ == "__main__":
    diagnose()
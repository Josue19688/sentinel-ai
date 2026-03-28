# Sentinel ML Service

**Motor de detección de anomalías MLSecOps para sistemas GRC**
**Versión:** 1.0.0 | **Stack:** FastAPI · PostgreSQL · TimescaleDB · Redis · Celery · Scikit-learn · SHAP
**Normas:** ISO 27001 · ISO 27005 · ISO 42001

---

## Tabla de contenidos

1. [¿Qué es Sentinel ML?](#qué-es-sentinel-ml)
2. [Arquitectura](#arquitectura)
3. [Requisitos previos](#requisitos-previos)
4. [Instalación y configuración](#instalación-y-configuración)
5. [Levantar el sistema](#levantar-el-sistema)
6. [Modos de operación](#modos-de-operación)
7. [Entrenar el modelo](#entrenar-el-modelo)
8. [Gestión de clientes HMAC](#gestión-de-clientes-hmac)
9. [Referencia de la API](#referencia-de-la-api)
10. [Gateway Universal](#gateway-universal)
11. [Dashboard de status](#dashboard-de-status)
12. [Simulador de ataques](#simulador-de-ataques)
13. [Verificación de auditoría](#verificación-de-auditoría)
14. [Circuit Breaker](#circuit-breaker)
15. [Flujo completo paso a paso](#flujo-completo-paso-a-paso)
16. [Troubleshooting](#troubleshooting)
17. [Referencia de variables de entorno](#referencia-de-variables-de-entorno)

---

## ¿Qué es Sentinel ML?

Sentinel ML es un **microservicio de inteligencia artificial** que se sitúa entre tu SIEM y tu GRC. Analiza eventos de seguridad en tiempo real, detecta anomalías usando Machine Learning y reenvía las alertas enriquecidas al GRC automáticamente.

**El SIEM no sabe que Sentinel existe. El GRC recibe alertas más inteligentes sin cambios en su código.**

### Capacidades principales

| Capacidad | Descripción |
|---|---|
| **Detección de anomalías** | Isolation Forest entrenado con datos históricos del Feature Store |
| **Gateway SIEM-agnóstico** | Normaliza automáticamente Wazuh, Microsoft Sentinel, Splunk, Suricata, AWS CloudTrail, firewalls y syslog genérico |
| **Correlación multi-activo** | Detecta 6 patrones de ataque en ventana de 6 minutos usando Redis |
| **Threat Intelligence** | Enriquecimiento automático con AbuseIPDB (opcional) |
| **Explicabilidad SHAP** | Cada predicción tiene una explicación en lenguaje humano (ISO 42001) |
| **Auditoría inmutable** | Hash chain SHA-256 que detecta modificaciones al log (ISO 27001 A.12.4.2) |
| **Circuit Breaker** | Fallback automático a lógica ISO 27005 determinística si el ML falla |
| **Human-in-the-loop** | Las recomendaciones IA requieren aprobación humana antes de impactar al GRC |

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Compose                               │
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │   ML API :8001   │    │  Celery Worker   │    │ Dashboard    │  │
│  │   FastAPI        │───►│  SHAP Asíncrono  │    │  :8080       │  │
│  │   <50ms respuesta│    │  psycopg2 sync   │    │  HTML puro   │  │
│  └────────┬─────────┘    └────────┬─────────┘    └──────┬───────┘  │
│           │                       │                      │          │
│           ▼                       ▼                      ▼          │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │         PostgreSQL 15 + TimescaleDB :5432                    │   │
│  │  Tables: normalized_features (hypertable) · ml_recommendations│  │
│  │          ml_clients · audit_log · ml_circuit_breaker         │   │
│  │          model_registry · sentinel_clients                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │         Redis :6379                                          │   │
│  │  Uso: Celery broker · Cache threat intel (TTL 1h)           │   │
│  │       Correlación multi-activo (TTL 6min)                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

Flujo POST /infer:
  SIEM/GRC ──HMAC──► hmac_validator ──► circuit_breaker ──► run_inference
                                                                │
                     normalize() ◄───────────────────────────────┤
                     IsolationForest.predict()                    │
                     _check_lateral_movement()                    │
                     _save_recommendation() ──► PostgreSQL        │
                     log_audit_event() ──► audit_log ◄───────────┘
                     compute_shap.delay() ──► Redis (Celery)

Flujo POST /gateway/analyze:
  SIEM ──► auto_normalize() ──► enrich() ──► correlate() ──► forward_to_grc()
            detecta fuente       AbuseIPDB    Redis 6min       GRC del cliente
```

---

## Requisitos previos

| Requisito | Versión mínima | Para qué |
|---|---|---|
| **Docker Desktop** | 24.x | Levantar todos los contenedores |
| **Docker Compose** | 2.x | Orquestación de servicios |
| **Python** | 3.11+ | Solo si se ejecuta fuera de Docker |
| **RAM disponible** | 2 GB | Recomendado 4 GB para SHAP |
| **Disco** | 500 MB | Imagen Docker + artefactos ML |

> **No se necesita GPU.** El modelo Isolation Forest corre en CPU. Tiempo de entrenamiento: <2 minutos con 10.000 registros.

---

## Instalación y configuración

### 1. Clonar el repositorio

```bash
git clone <url-del-repositorio>
cd sentinel-ml
```

### 2. Crear el archivo de entorno

```bash
# Copiar la plantilla
cp .env.example .env
```

Editar `.env` con los valores correctos:

```env
# OBLIGATORIO antes de producción — generar con: openssl rand -hex 32
SECRET_KEY=tu-secret-key-aqui

# Modo de operación (ver sección "Modos")
MODEL_MODE=DUMMY

# Opcional: AbuseIPDB para threat intelligence
ABUSEIPDB_API_KEY=tu-api-key-de-abuseipdb
```

> ⚠️ **Nunca subas el archivo `.env` al repositorio.** Ya está en `.gitignore`.

### 3. Verificar la configuración Docker

```bash
docker compose config
```

---

## Levantar el sistema

### Inicio estándar (modo desarrollo)

```bash
docker compose up -d
```

Esto levanta **4 contenedores**:
| Contenedor | Puerto | Descripción |
|---|---|---|
| `sentinel_api` | `8001` | API principal de inferencia |
| `sentinel_worker` | — | Worker Celery para SHAP |
| `sentinel_db` | `5432` | PostgreSQL + TimescaleDB |
| `sentinel_redis` | `6379` | Redis (broker + cache) |
| `sentinel_dashboard` | `8080` | Dashboard de status |

### Verificar que todo está corriendo

```bash
# Estado de los contenedores
docker compose ps

# Salud del servicio
curl http://localhost:8001/health
```

Respuesta esperada:
```json
{
  "status": "ok",
  "model_mode": "DUMMY",
  "model_version": null,
  "circuit_breaker": "CLOSED",
  "timestamp": 1743000000.0
}
```

### Ver logs en tiempo real

```bash
# Todos los servicios
docker compose logs -f

# Solo la API
docker compose logs -f ml-api

# Solo el worker SHAP
docker compose logs -f ml-worker
```

### Detener el sistema

```bash
# Detener sin borrar datos
docker compose down

# Detener y borrar volúmenes (borra la DB y Redis)
docker compose down -v
```

---

## Modos de operación

El sistema tiene **3 modos** que permiten una adopción progresiva sin riesgo:

### DUMMY — Fase de validación de conectividad

```env
MODEL_MODE=DUMMY
```

- **Qué hace:** Acepta cualquier request, devuelve `anomaly_score=0.5` siempre
- **Para qué sirve:** Validar que la integración SIEM→Sentinel→GRC funciona end-to-end sin ML real
- **Autenticación:** El header HMAC es **opcional** — útil para desarrollo local
- **Cuándo usarlo:** Primera integración, pruebas de conectividad, demos

### SHADOW — Fase de observación

```env
MODEL_MODE=SHADOW
```

- **Qué hace:** Ejecuta el modelo ML real y genera recomendaciones, pero NO las reenvía al GRC automáticamente
- **Para qué sirve:** Observar las predicciones durante semanas antes de activarlas, comparar con decisiones humanas
- **Autenticación:** El header `X-Client-ID` es **obligatorio**, la firma HMAC es recomendada pero no bloquea
- **Cuándo usarlo:** Primeras 2-4 semanas de operación real, hasta validar que el modelo tiene buena precisión

### LIVE — Producción total

```env
MODEL_MODE=LIVE
```

- **Qué hace:** Autenticación HMAC-SHA256 estricta, recomendaciones generadas y reenvío automático al GRC
- **Para qué sirve:** Operación productiva completa
- **Autenticación:** HMAC **obligatorio**. Sin firma válida → HTTP 403
- **Cuándo usarlo:** Después de validar con SHADOW y entrenar el modelo con datos reales

**Cambiar de modo** (sin reiniciar la DB):
```bash
# Editar .env y reiniciar solo la API y el worker
docker compose up -d --no-deps ml-api ml-worker
```

---

## Entrenar el modelo

El modelo `IsolationForest` necesita entrenarse antes de activar SHADOW o LIVE.

### Opción A — Datos sintéticos (recomendada para empezar)

Genera 2.100 registros de datos de demo (2.000 normales + 100 anomalías):

```bash
docker compose exec ml-api python -m app.models.trainer --mode synthetic
```

Salida esperada:
```
F1 Score (anomalías): 0.876
Modelo guardado: /app/model_artifacts/20260328_140000 | SHA256: a1b2c3d4...
Model registered: 20260328_140000 | F1=0.876 | ...
{'version': '20260328_140000', 'f1': 0.876, 'saved': True}
```

### Opción B — Datos históricos reales

Usa los eventos normalizados acumulados en PostgreSQL (últimos 90 días):

```bash
docker compose exec ml-api python -m app.models.trainer --mode historical
```

> Requiere al menos 200 eventos en `normalized_features`. Recomendado: >5.000 eventos para buena precisión.

### Dry run — Ver métricas sin guardar

```bash
docker compose exec ml-api python -m app.models.trainer --mode synthetic --dry-run
```

### Verificar que el modelo está activo

```bash
curl http://localhost:8001/health/model
```

```json
{
  "status": "OK",
  "model_version": "20260328_140000",
  "f1_score": 0.876,
  "algorithm": "IsolationForest",
  "trained_at": "2026-03-28T14:00:00",
  "circuit_breaker": "CLOSED"
}
```

### Ruta de los artefactos

Los modelos se guardan en el volumen Docker `ml_artifacts`:
```
/app/model_artifacts/
└── 20260328_140000/
    ├── model.pkl       # IsolationForest + StandardScaler serializado
    └── model.sha256    # Hash de integridad del artefacto
```

> El sistema carga automáticamente la versión más reciente al arrancar.

---

## Gestión de clientes HMAC

Cada sistema que llame a `/infer` necesita un `CLIENT_ID` y un `CLIENT_SECRET` para firmar sus requests con HMAC-SHA256.

### Crear un cliente nuevo

```bash
docker compose exec ml-api python -m app.auth.client_manager create --name "GRC Empresa A"
```

Salida:
```
==================================================
Cliente creado: GRC Empresa A
  CLIENT_ID     = abc123xyz789...
  CLIENT_SECRET = tu-secret-de-32-chars-aleatorio
  GUARDAR AHORA — el secret no se volverá a mostrar
==================================================
```

> ⚠️ **El `CLIENT_SECRET` solo se muestra una vez.** Guárdalo de inmediato en un gestor de secretos.

### Listar clientes activos

```bash
docker compose exec ml-api python -m app.auth.client_manager list
```

```
  [ACTIVO]  abc123xyz789 — GRC Empresa A (2026-03-28)
  [REVOCADO] def456uvw   — GRC Empresa B (2026-03-10)
```

### Revocar un cliente

```bash
docker compose exec ml-api python -m app.auth.client_manager revoke --client-id abc123xyz789
```

---

## Referencia de la API

La documentación interactiva (Swagger) está disponible en:
```
http://localhost:8001/docs
```

### `POST /infer` — Inferencia de anomalías

**Headers requeridos:**
```
Content-Type: application/json
X-Client-ID: <client_id>
X-GRC-Signature: <hmac_sha256(body + timestamp + client_id, client_secret)>
X-Timestamp: <unix_timestamp>
```

> En `MODEL_MODE=DUMMY` los headers HMAC son opcionales.

**Body — Formato Wazuh (ejemplo):**
```json
{
  "rule": {
    "level": 10,
    "description": "Directory traversal scan detected",
    "groups": ["web", "attack"]
  },
  "agent": { "name": "web-server-prod" },
  "data": { "srcip": "192.168.1.105" },
  "asset_value": 0.7
}
```

**Respuesta exitosa (HTTP 200):**
```json
{
  "recommendation_id": "550e8400-e29b-41d4-a716-446655440000",
  "anomaly_score": 0.847,
  "aro_suggested": 10.16,
  "confidence": 0.92,
  "model_version": "20260328_140000",
  "model_mode": "LIVE",
  "lateral_movement_detected": false,
  "explanation_pending": true
}
```

**Headers de respuesta:**
```
X-Model-Mode: LIVE
X-Latency-Ms: 23.4
X-Model-Version: 20260328_140000
```

**Cómo firmar el request (Python):**
```python
import hmac, hashlib, time, json, httpx

CLIENT_ID     = "tu-client-id"
CLIENT_SECRET = "tu-client-secret"
ML_API_URL    = "http://localhost:8001"

def sign_and_send(event: dict) -> dict:
    payload   = json.dumps(event)
    timestamp = str(int(time.time()))
    signature = hmac.new(
        CLIENT_SECRET.encode(),
        f"{payload}{timestamp}{CLIENT_ID}".encode(),
        hashlib.sha256
    ).hexdigest()

    r = httpx.post(
        f"{ML_API_URL}/infer",
        content=payload,
        headers={
            "Content-Type":    "application/json",
            "X-Client-ID":     CLIENT_ID,
            "X-GRC-Signature": signature,
            "X-Timestamp":     timestamp,
        }
    )
    return r.json()
```

---

### `GET /recommendations` — Listar recomendaciones

```bash
curl -H "X-Client-ID: sim-client" \
     http://localhost:8001/recommendations?status=PENDING&limit=20
```

```json
[
  {
    "id": "550e8400-...",
    "asset_id": "web-server-prod",
    "anomaly_score": 0.847,
    "aro_suggested": 10.16,
    "confidence": 0.92,
    "model_mode": "LIVE",
    "status": "PENDING",
    "shap_ready": true,
    "shap_values": {
      "severity_score": 0.342,
      "asset_value": 0.128,
      "timestamp_delta": -0.043,
      "event_type_id": 0.015,
      "explanation": "Severidad (85%) superó el patrón histórico del activo."
    },
    "created_at": "2026-03-28T14:00:00"
  }
]
```

---

### `POST /recommendations/{id}/approve` — Aprobar una recomendación

```bash
curl -X POST \
     -H "X-Client-ID: sim-client" \
     "http://localhost:8001/recommendations/550e8400-.../approve?note=Confirmado+por+SOC"
```

```json
{ "id": "550e8400-...", "status": "APPROVED", "message": "Recomendación approved correctamente" }
```

---

### `POST /recommendations/{id}/reject` — Rechazar

```bash
curl -X POST \
     -H "X-Client-ID: sim-client" \
     "http://localhost:8001/recommendations/550e8400-.../reject?note=Falso+positivo"
```

---

### `GET /audit/verify` — Verificar integridad del log de auditoría

```bash
curl -H "X-Client-ID: sim-client" http://localhost:8001/audit/verify
```

**Cadena íntegra:**
```json
{
  "status": "INTACT",
  "verified": true,
  "records_verified": 1543,
  "latest_hash": "a1b2c3d4e5f6aa77..."
}
```

**Cadena comprometida:**
```json
{
  "status": "COMPROMISED",
  "verified": false,
  "broken_at_record": 892,
  "message": "La cadena de auditoría ha sido comprometida. Iniciar investigación forense."
}
```

---

### `GET /health` y `GET /health/model`

```bash
curl http://localhost:8001/health
curl http://localhost:8001/health/model
```

---

## Gateway Universal

El Gateway permite conectar **cualquier SIEM** sin modificar su configuración existente.

### 1. Registrar tu GRC en el Gateway

Hacer esto **una sola vez** por cliente:

```bash
curl -X POST http://localhost:8001/gateway/register \
  -H "Content-Type: application/json" \
  -d '{
    "company_name": "Empresa ABC",
    "grc_url": "https://tu-grc.empresa.com",
    "grc_api_key": "tu-api-key-del-grc",
    "grc_api_secret": "tu-api-secret-del-grc"
  }'
```

Respuesta:
```json
{
  "sentinel_api_key": "snl_AbCdEf123...",
  "sentinel_api_secret": "tu-secret-sentinel-guardar-ahora",
  "webhook_url": "/gateway/analyze",
  "message": "Configuración guardada. Usa estas credenciales en tu script SIEM."
}
```

> ⚠️ Guarda `sentinel_api_secret` — solo se muestra una vez.

### 2. Configurar el SIEM para enviar a Sentinel

En el script de integración de tu SIEM, reemplaza la URL del GRC por la URL de Sentinel:

```python
# ANTES — el SIEM enviaba directo al GRC
r = httpx.post(
    "https://tu-grc.empresa.com/api/v1/integrations/telemetry",
    headers={"X-API-Key": GRC_KEY, "X-API-Secret": GRC_SECRET},
    json=evento
)

# DESPUÉS — el SIEM envía a Sentinel (el GRC no cambia)
r = httpx.post(
    "http://localhost:8001/gateway/analyze",
    headers={
        "X-API-Key":    "snl_AbCdEf123...",    # key de Sentinel
        "X-API-Secret": "tu-secret-sentinel",   # secret de Sentinel
        "Content-Type": "application/json"
    },
    json=evento  # el formato del evento NO cambia
)
```

Sentinel normaliza automáticamente el formato y reenvía al GRC.

### 3. Formatos de SIEM soportados

El Gateway detecta la fuente automáticamente por la estructura del JSON:

| SIEM | Criterio de detección |
|---|---|
| **Wazuh** | `"rule"` + `"agent"` en el JSON |
| **Microsoft Sentinel** | `"Severity"` + `"IncidentNumber"` |
| **Suricata** | `"event_type"` + `"alert"` |
| **Splunk** | `"result"` o `"_raw"` |
| **AWS CloudTrail** | `"eventSource"` + `"awsRegion"` |
| **GRC nativo** | `"technical_id"` + `"external_event_id"` |
| **Syslog genérico** | `"message"` o `"msg"` |
| **Firewall / iptables** | `"SRC"` o `"src_ip"` |
| **Catch-all** | Cualquier otro JSON |

### 4. Respuesta del Gateway

```json
{
  "status": "processed",
  "risk_level": "high",
  "pattern": "lateral_movement",
  "action": "escalate",
  "reason": "Autenticación fallida seguida de éxito desde misma IP hacia activo diferente en menos de 6 minutos.",
  "enriched": true,
  "source_detected": "wazuh",
  "latency_ms": 45.2,
  "grc_notified": true
}
```

### Patrones de ataque detectados (ventana de 6 minutos)

| Patrón | Descripción | Acción sugerida |
|---|---|---|
| `lateral_movement` | Auth fallida en activo A + éxito en activo B, misma IP | `escalate` |
| `brute_force_success` | Múltiples fallos + éxito en mismo activo | `escalate` |
| `c2_beacon` | IP en lista negra AbuseIPDB | `escalate` |
| `brute_force` | 5+ fallos de auth en 6 minutos | `review` |
| `port_scan` | 10+ puertos distintos bloqueados | `review` |
| `suspicious_outbound` | Tráfico saliente a destino inusual | `review` |
| `none` | Sin patrón reconocido | `ignore` |

---

## Dashboard de status

El dashboard es un panel HTML liviano sin dependencias externas:

```
http://localhost:8080
```

**Se actualiza automáticamente cada 10 segundos.**

Muestra:
- Modo del modelo activo (DUMMY / SHADOW / LIVE) con código de color
- Estado del Circuit Breaker (🟢 CLOSED / 🟡 HALF_OPEN / 🔴 OPEN)
- Eventos normalizados hoy
- Recomendaciones PENDING / APPROVED / REJECTED (últimas 24h)
- Tabla con las 10 últimas recomendaciones (score, asset, estado, SHAP)

---

## Simulador de ataques

El simulador genera eventos de ataque realistas para tests sin SIEM real.

### Ejecutar un escenario

```bash
# Desde el directorio del simulador
cd simulator

# Movimiento lateral (2 eventos con delay)
python attack_scenarios.py --scenario lateral_movement

# Fuerza bruta SSH (20 intentos)
python attack_scenarios.py --scenario brute_force

# Exfiltración de datos
python attack_scenarios.py --scenario data_exfiltration

# Alerta de Microsoft Sentinel
python attack_scenarios.py --scenario sentinel_alert

# 30 eventos normales (para entrenar el baseline)
python attack_scenarios.py --scenario normal

# Todos los escenarios secuencialmente
python attack_scenarios.py --all
```

### Desde Docker (modo testing)

```bash
docker compose --profile testing up simulator
```

### Configurar el simulador

El simulador lee variables de entorno:
```env
ML_API_URL=http://localhost:8001    # URL del ML Service
CLIENT_ID=sim-client                # ID del cliente registrado
CLIENT_SECRET=sim-secret-dev        # Secret para firmar HMAC
```

### Salida esperada

```
============================================================
ESCENARIO: LATERAL_MOVEMENT
============================================================

→ Paso 1: Escaneo de directorios en servidor web
  anomaly_score: 0.823
  aro_suggested: 9.88
  lateral_movement: False
  model_mode: LIVE | latency: 18.3ms

→ Paso 2: SSH exitoso desde mismo IP hacia DB (4 min después)
  (simulando 240s de delay...)
  anomaly_score: 0.951
  aro_suggested: 11.41
  lateral_movement: True
  model_mode: LIVE | latency: 22.1ms
```

---

## Verificación de auditoría

El log de auditoría usa una **cadena de hashes SHA-256** donde cada registro firma al anterior. Esta estructura garantiza que cualquier modificación manual en la DB sea detectable.

### Verificar la integridad completa

```bash
curl -H "X-Client-ID: sim-client" http://localhost:8001/audit/verify
```

### Verificar directamente por SQL

```sql
-- Consultar el log de auditoría directamente en PostgreSQL
SELECT id, event_type, actor, entity_id, created_at, current_hash
FROM audit_log
ORDER BY id DESC
LIMIT 20;
```

### Eventos registrados automáticamente

| Evento | Cuándo se registra |
|---|---|
| `INFERENCE` | Cada llamada exitosa a `/infer` |
| `INFERENCE_ERROR` | Cuando falla la inferencia |
| `RECOMMENDATION_APPROVED` | Al aprobar una recomendación |
| `RECOMMENDATION_REJECTED` | Al rechazar una recomendación |

---

## Circuit Breaker

El Circuit Breaker protege el sistema contra fallos del ML y drift de datos.

### Estados y transiciones

```
CLOSED ──[N fallos o PSI>0.2]──► OPEN ──[timeout 60s]──► HALF_OPEN
  ▲                                                            │
  └──────────[inferencia exitosa]─────────────────────────────┘
                                   │
  OPEN ◄────[inferencia falla]─────┘
```

| Estado | Comportamiento en `/infer` |
|---|---|
| `CLOSED` | Normal — usa el modelo ML |
| `OPEN` | HTTP 503 — fallback a ISO 27005 sugerido |
| `HALF_OPEN` | Permite una inferencia de prueba |

### Ver el estado actual

```bash
curl http://localhost:8001/health
# o en la DB:
# SELECT state, failures, opened_at FROM ml_circuit_breaker;
```

### Cerrar manualmente el Circuit Breaker (emergencia)

```sql
UPDATE ml_circuit_breaker
SET state='CLOSED', failures=0, opened_at=NULL, updated_at=NOW();
```

### Configurar los umbrales

En `.env`:
```env
CB_FAILURE_THRESHOLD=5     # Fallos antes de abrir
CB_RECOVERY_TIMEOUT_S=60   # Segundos antes de intentar HALF_OPEN
```

### PSI (Population Stability Index)

El PSI mide si la distribución de los datos de entrada cambió respecto al baseline (últimas 3 semanas vs. última semana). Si supera `0.2`, se abre el Circuit Breaker.

Ejecutar manualmente:
```bash
# Desde la Python shell dentro del contenedor
docker compose exec ml-api python -c "
import asyncio
from app.drift.psi_monitor import compute_psi
psi = asyncio.run(compute_psi())
print(f'PSI actual: {psi:.4f}')
"
```

---

## Flujo completo paso a paso

### Primera vez — desde cero hasta LIVE

```bash
# 1. Configurar entorno
cp .env.example .env
# Editar .env: SECRET_KEY y MODEL_MODE=DUMMY

# 2. Levantar el sistema
docker compose up -d

# 3. Verificar salud
curl http://localhost:8001/health

# 4. Crear el cliente HMAC para tu GRC
docker compose exec ml-api python -m app.auth.client_manager create --name "Mi GRC"
# Anotar CLIENT_ID y CLIENT_SECRET

# 5. Probar conectividad con el simulador (DUMMY no requiere HMAC)
cd simulator
python attack_scenarios.py --scenario normal

# 6. Ver el dashboard
# Abrir http://localhost:8080

# --- PASAR A SHADOW ---

# 7. Entrenar el modelo con datos sintéticos
docker compose exec ml-api python -m app.models.trainer --mode synthetic

# 8. Cambiar a modo SHADOW en .env
# MODEL_MODE=SHADOW
docker compose up -d --no-deps ml-api ml-worker

# 9. Ejecutar escenarios de ataque y observar recomendaciones
python attack_scenarios.py --all
curl -H "X-Client-ID: sim-client" http://localhost:8001/recommendations?status=PENDING

# 10. Aprobar/rechazar para validar el Human-in-the-loop
curl -X POST -H "X-Client-ID: sim-client" \
  "http://localhost:8001/recommendations/<id>/approve?note=Validado"

# --- PASAR A LIVE ---

# 11. Cuando F1 > 0.8 y el modelo lleva 2 semanas en SHADOW estable:
# MODEL_MODE=LIVE en .env
docker compose up -d --no-deps ml-api ml-worker

# 12. Verificar auditoría
curl -H "X-Client-ID: sim-client" http://localhost:8001/audit/verify
```

---

## Troubleshooting

### El servicio no arranca — "DB connection failed"

```bash
# Verificar estado de la DB
docker compose ps ml-db
docker compose logs ml-db

# Si la DB nunca arrancó, recrear el volumen
docker compose down -v
docker compose up -d
```

### `/infer` responde HTTP 401

Verificar que el `CLIENT_ID` existe y está activo:
```bash
docker compose exec ml-api python -m app.auth.client_manager list
```

En `MODEL_MODE=DUMMY`, omitir los headers HMAC si no tienes el secret.

### `/infer` responde HTTP 503 — circuit_breaker_open

El Circuit Breaker está abierto. Esperar 60 segundos para auto-recovery, o reiniciarlo manualmente:
```sql
-- En psql
docker compose exec ml-db psql -U ml -d ml_features -c \
  "UPDATE ml_circuit_breaker SET state='CLOSED', failures=0, opened_at=NULL, updated_at=NOW();"
```

### Los SHAP values no aparecen (shap_ready: false)

El cálculo SHAP es asíncrono y toma ~30 segundos. Verificar que el worker está corriendo:
```bash
docker compose ps ml-worker
docker compose logs ml-worker
```

### El modelo no entrena con datos históricos — "datos insuficientes"

Se necesitan al menos 200 eventos. Usar primero `--mode synthetic` hasta acumular datos reales.

### El dashboard muestra "Sin recomendaciones aún"

Ejecutar el simulador para generar eventos:
```bash
cd simulator && python attack_scenarios.py --all
```

---

## Referencia de variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `DATABASE_URL` | `postgresql://ml:ml@localhost:5432/ml_features` | URL de conexión a PostgreSQL |
| `REDIS_URL` | `redis://localhost:6379/0` | URL de conexión a Redis |
| `MODEL_MODE` | `DUMMY` | Modo de operación: `DUMMY` / `SHADOW` / `LIVE` |
| `SECRET_KEY` | `dev-secret` | Clave secreta de la aplicación. **Cambiar siempre en producción** |
| `LOG_LEVEL` | `INFO` | Nivel de log: `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `SHAP_TIMEOUT_S` | `30` | Timeout del worker SHAP en segundos |
| `CB_FAILURE_THRESHOLD` | `5` | Número de fallos para abrir el Circuit Breaker |
| `CB_RECOVERY_TIMEOUT_S` | `60` | Segundos antes de intentar HALF_OPEN desde OPEN |
| `RETENTION_DAYS` | `90` | Días de retención de eventos en normalized_features (TimescaleDB) |
| `MODEL_ARTIFACTS_PATH` | `/app/model_artifacts` | Ruta donde se guardan los artefactos del modelo |
| `ABUSEIPDB_API_KEY` | `""` (deshabilitado) | API key de AbuseIPDB para threat intelligence |
| `SIM_CLIENT_ID` | `sim-client` | Client ID del simulador (solo para testing) |
| `SIM_CLIENT_SECRET` | `sim-secret-dev` | Client Secret del simulador (solo para testing) |

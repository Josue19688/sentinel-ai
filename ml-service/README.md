# Sentinel ML Service

**Motor de deteccion de anomalias MLSecOps para sistemas GRC**
**Version:** 2.0.0 | **Stack:** FastAPI · PostgreSQL · Redis · Celery · River ML · IsolationForest · SHAP
**Normas:** ISO 27001 · ISO 27005 · ISO 42001

---

## Tabla de contenidos

1. [Que es Sentinel ML?](#que-es-sentinel-ml)
2. [Arquitectura](#arquitectura)
3. [Estructura del proyecto](#estructura-del-proyecto)
4. [Requisitos previos](#requisitos-previos)
5. [Instalacion y configuracion](#instalacion-y-configuracion)
6. [Levantar el sistema](#levantar-el-sistema)
7. [Modos de operacion](#modos-de-operacion)
8. [Autenticacion](#autenticacion)
9. [Referencia de la API](#referencia-de-la-api)
10. [Gateway Universal SIEM](#gateway-universal-siem)
11. [Dashboard de status](#dashboard-de-status)
12. [Entrenar el modelo](#entrenar-el-modelo)
13. [Simulador de ataques](#simulador-de-ataques)
14. [Circuit Breaker](#circuit-breaker)
15. [Verificacion de auditoria](#verificacion-de-auditoria)
16. [Variables de entorno](#variables-de-entorno)
17. [Troubleshooting](#troubleshooting)

---

## Que es Sentinel ML?

Sentinel ML es un **microservicio de inteligencia artificial para seguridad** que se posiciona entre tu SIEM y tu GRC.
Analiza eventos en tiempo real con un pipeline hibrido de deteccion (River ML streaming + IsolationForest) y reenvía
alertas enriquecidas al GRC de forma automatica.

**El SIEM no necesita cambiar. El GRC recibe alertas mas inteligentes sin modificar su codigo.**

### Capacidades principales

| Capacidad | Descripcion |
|---|---|
| **Pipeline hibrido ML** | Capa 1: KafkaFilter (ruido) · Capa 2: River ML streaming · Capa 3: IsolationForest async |
| **Gateway SIEM-agnostico** | Normaliza Wazuh, Sentinel, Splunk, Suricata, AWS CloudTrail, QRadar, firewalls y syslog |
| **Correlacion multi-activo** | Detecta 6 patrones de ataque en ventana de 6 minutos usando Redis |
| **Riesgo cuantitativo ISO 27005** | ARO, ALE, EF calculados automaticamente por activo |
| **Explicabilidad SHAP** | Cada prediccion tiene explicacion en lenguaje humano (ISO 42001) |
| **Auditoria inmutable** | Hash chain SHA-256 detectable de modificaciones (ISO 27001 A.12.4.2) |
| **Circuit Breaker** | Fallback automatico a logica ISO 27005 deterministica si el ML falla |
| **Autenticacion dual** | JWT Bearer (humanos/dashboard) + API Key (SIEM/maquinas) |
| **Sandbox forense** | Subida de archivos JSON/JSONL para analisis con motor forense |

---

## Arquitectura

```
SIEM (Wazuh / Splunk / QRadar / ...)
         |
         v  POST /gateway/analyze  (X-API-Key)
 +-------+--------+
 |  Gateway Layer |  -- Normalizer -- Enricher -- Correlator
 +-------+--------+
         |
   +-----+------+
   |  Capa 1    |  KafkaFilter -- filtra ruido (severity < 0.05, heartbeats)
   +-----+------+
         |
   +-----+------+
   |  Capa 2    |  River ML -- deteccion streaming por activo (warm/cold)
   |            |  NmapDetector -- escaneo de puertos (matematico puro)
   +-----+------+
         |  si anomalia
   +-----+------+
   |  Capa 3    |  IsolationForest -- confirmacion asincrona (Celery)
   |            |  SHAP Explainer  -- explicabilidad XAI
   +-----+------+
         |
         v
      GRC Service  (telemetria + alertas ISO 27001 + metricas ARO/ALE)


Servicios Docker:
  sentinel_api      :8001  FastAPI (inferencia + gateway + auth)
  sentinel_worker   ---    Celery (IsolationForest + SHAP + riesgo)
  sentinel_db       :5432  PostgreSQL (features + recomendaciones + auditoria)
  sentinel_redis    :6379  Redis (broker Celery + correlaciones + sandbox cache)
```

---

## Estructura del proyecto

```
sentinel-ml/
|-- .env.example              plantilla de variables de entorno
|-- .env                      variables reales (NO en git)
|-- docker-compose.yml
|-- README.md
|
|-- simulator/                generador de ataques para testing
|   |-- attack_scenarios.py
|   |-- sentinel_integration.py
|   `-- stress-testing.py
|
|-- scripts/                  utilidades de administracion (no son tests)
|   |-- init_db.sql
|   |-- diagnostico.py
|   |-- force_train.py
|   |-- validate_sigmoid.py
|   `-- client_manager_hmac.py
|
`-- ml-service/
    |-- Dockerfile
    |-- pytest.ini
    |-- model_artifacts/      modelos entrenados (volumen Docker)
    |-- migrations/           SQL de esquema de base de datos
    |   |-- 001_auth_users.sql
    |   |-- 002_auth_api_keys.sql
    |   `-- 003_risk_metrics.sql
    |
    |-- tests/
    |   |-- fixtures/         datos de prueba (JSON, TXT)
    |   |-- integration/      tests de integracion (pytest + Docker)
    |   |-- test_all.py
    |   |-- test_fase1_integracion.py
    |   |-- test_normalizer_multisiem.py
    |   |-- test_phase2_risk.py
    |   `-- test_phase3_mlops.py
    |
    `-- app/
        |-- config.py         variables de entorno validadas con Pydantic
        |-- db.py             pool asyncpg + cliente Redis
        |-- main.py           FastAPI app, routers, middlewares CORS
        |-- worker.py         punto de entrada Celery
        |
        |-- api/              routers HTTP (solo reciben y delegan)
        |   |-- auth_router.py     registro, login, refresh, logout
        |   |-- keys_router.py     CRUD de API Keys
        |   |-- trainer_router.py  endpoints MLOps (retrain, versions)
        |   `-- recommendations.py aprobar/rechazar recomendaciones IA
        |
        |-- auth/             autenticacion y autorizacion
        |   |-- dependencies.py    Depends: get_current_user, get_current_api_client
        |   |-- jwt_handler.py     crear/decodificar tokens JWT
        |   |-- api_key_manager.py split, hash, verify de API Keys
        |   `-- password.py        bcrypt hashing
        |
        |-- audit/            trazabilidad ISO 27001
        |   `-- hash_chain.py      log inmutable con SHA-256 encadenado
        |
        |-- calculator/       cuantificacion de riesgo ISO 27005
        |   |-- risk.py            ARO/ALE/EF rapido (para gateway)
        |   `-- risk_engine.py     motor completo con persistencia historica
        |
        |-- celery/           infraestructura Celery
        |   |-- celery_app.py      instancia y configuracion de Celery
        |   `-- db.py              conexion sincrona psycopg2 para workers
        |
        |-- dashboard/        UI de estado (HTML puro, sin dependencias)
        |   `-- dashboard.py
        |
        |-- detection/        modelos de deteccion ML en streaming
        |   |-- kafka_filter.py    Capa 1: filtro de ruido con rate limiting
        |   |-- river_detector.py  Capa 2: River ML por activo
        |   `-- nmap_detector.py   detector de escaneo de puertos (matematico)
        |
        |-- drift/            monitoreo de drift del modelo
        |   `-- psi_monitor.py     PSI + control del Circuit Breaker
        |
        |-- gateway/          punto de entrada SIEM (proxy universal)
        |   |-- router.py          endpoints: /register, /analyze, /sandbox
        |   |-- enricher.py        threat intel + geolocalizacion
        |   |-- correlator.py      correlacion multi-activo (Redis, 6 min)
        |   |-- grc_forwarder.py   reenvio de alertas al GRC
        |   `-- store.py           registro de clientes SIEM
        |
        |-- models/           ciclo de vida del modelo ML
        |   |-- inferrer.py        ejecutar inferencia (<50ms)
        |   |-- registry.py        registro de versiones activas
        |   `-- trainer.py         entrenamiento continuos IsolationForest
        |
        |-- normalizer/       normalizacion de logs SIEM-agnostica
        |   |-- universal.py       entrada principal (detecta formato automatico)
        |   |-- pattern_classifier.py clasificacion de patrones de ataque
        |   `-- semantic_extractor.py extraccion semantica de campos
        |
        |-- sandbox/          motor forense para analisis de archivos
        |   |-- engine.py          orquestador del analisis
        |   |-- asset_discovery.py identificacion de activos en el payload
        |   |-- explainer.py       generacion de explicaciones SHAP
        |   |-- iot.py             deteccion especifica de activos IoT
        |   `-- scoring.py         puntuacion de riesgo forense
        |
        |-- security/         sanitizacion y validacion de inputs
        |   `-- sanitizer.py
        |
        `-- tasks/            tareas Celery organizadas por responsabilidad
            |-- ingest.py          Capa 2+3: River ML + encolado a Forest
            |-- escalate_task.py   Capa 3: IsolationForest asincrono
            |-- shap_task.py       calculo de explicabilidad SHAP
            `-- risk_task.py       calculo ARO/ALE periodico + sandbox
```

---

## Requisitos previos

| Requisito | Version minima | Para que |
|---|---|---|
| **Docker Desktop** | 24.x | Levantar todos los contenedores |
| **Docker Compose** | 2.x | Orquestacion de servicios |
| **Python** | 3.11+ | Solo si se ejecuta fuera de Docker |
| **RAM disponible** | 2 GB | Recomendado 4 GB para SHAP |

> No se necesita GPU. El modelo Isolation Forest corre en CPU.

---

## Instalacion y configuracion

### 1. Clonar el repositorio

```bash
git clone <url-del-repositorio>
cd sentinel-ml
```

### 2. Crear el archivo de entorno

```bash
cp .env.example .env
```

Editar `.env` con los valores reales. Campos obligatorios antes de produccion:

```env
# Generar con: openssl rand -hex 32
SECRET_KEY=

# Generar con: openssl rand -hex 64
JWT_SECRET_KEY=

# URL e credenciales de tu instancia GRC
DEV_GRC_URL=https://tu-grc.empresa.com
DEV_GRC_API_KEY=
DEV_GRC_API_SECRET=

# Origenes permitidos para CORS (separados por coma)
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# Modo de operacion
MODEL_MODE=DUMMY
```

> NUNCA subas el archivo `.env` al repositorio. Ya esta en `.gitignore`.

### 3. Verificar configuracion

```bash
docker compose config
```

---

## Levantar el sistema

```bash
docker compose up -d
```

Contenedores que se levantan:

| Contenedor | Puerto | Descripcion |
|---|---|---|
| `sentinel_api` | `8001` | API principal (inferencia + gateway + auth) |
| `sentinel_worker` | --- | Worker Celery (IsolationForest + SHAP + riesgo) |
| `sentinel_db` | `5432` | PostgreSQL |
| `sentinel_redis` | `6379` | Redis (broker + cache + correlaciones) |

```bash
# Verificar estado
docker compose ps

# Health check
curl http://localhost:8001/health

# Ver logs en tiempo real
docker compose logs -f ml-api
docker compose logs -f ml-worker
```

Respuesta esperada del health check:
```json
{
  "status": "ok",
  "model_mode": "SHADOW",
  "model_version": "20260330_144533",
  "circuit_breaker": "CLOSED",
  "timestamp": 1775331491.55
}
```

---

## Modos de operacion

| Modo | Que hace | Cuando usarlo |
|---|---|---|
| `DUMMY` | Devuelve score=0.5 siempre, sin ML real | Primera integracion, tests de conectividad |
| `SHADOW` | Corre ML real, genera recomendaciones, NO impacta GRC | Primeras semanas, validar precision |
| `LIVE` | Operacion completa, reenvio automatico al GRC | Produccion validada |

Cambiar de modo sin reiniciar la DB:
```bash
# Editar MODEL_MODE en .env
docker compose up -d --no-deps ml-api ml-worker
```

---

## Autenticacion

El sistema tiene **dos mecanismos independientes** segun el tipo de actor:

### Para humanos (JWT Bearer)

Usado por el dashboard o frontend. Flujo completo con refresh tokens.

```bash
# 1. Registrar usuario
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@empresa.com","password":"SecurePass123","role":"admin"}'

# 2. Login -> recibe access_token + refresh_token
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@empresa.com","password":"SecurePass123"}'

# 3. Usar el access_token
curl -H "Authorization: Bearer <access_token>" http://localhost:8001/audit/verify
```

Caracteristicas del JWT:
- Access token: 60 minutos (configurable con `ACCESS_TOKEN_EXPIRE_MINUTES`)
- Refresh token: 7 dias (configurable con `REFRESH_TOKEN_EXPIRE_DAYS`)
- Blacklist en Redis para logout inmediato
- Version counter en DB para invalidacion masiva (cambio de password)

### Para maquinas / SIEM (API Key)

Usado por integraciones automaticas. Sin expiracion por defecto, revocable en cualquier momento.

```bash
# 1. Crear API Key (requiere JWT admin)
curl -X POST http://localhost:8001/keys \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Wazuh Produccion","scopes":["ingest:write","recommendations:read"]}'

# Respuesta: guarda el secret ahora, no se vuelve a mostrar
# { "key": "snl_<prefix>.<secret>", "key_id": "..." }

# 2. Usar la API Key en requests
curl -H "X-API-Key: snl_abc123.secretXYZ" http://localhost:8001/recommendations
```

---

## Referencia de la API

Documentacion interactiva (Swagger): `http://localhost:8001/docs`

### POST /infer — Inferencia de anomalias

```bash
curl -X POST http://localhost:8001/infer \
  -H "X-API-Key: snl_<key>" \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {"level": 10, "description": "Directory traversal"},
    "agent": {"name": "web-server-prod"},
    "data": {"srcip": "192.168.1.105"},
    "asset_value": 0.7
  }'
```

Respuesta:
```json
{
  "recommendation_id": "550e8400-e29b-41d4-a716-446655440000",
  "anomaly_score": 0.847,
  "aro_suggested": 10.16,
  "confidence": 0.92,
  "model_version": "20260330_144533",
  "model_mode": "SHADOW",
  "lateral_movement_detected": false,
  "explanation_pending": true
}
```

Headers de respuesta:
```
X-Model-Mode: SHADOW
X-Latency-Ms: 23.4
X-Model-Version: 20260330_144533
```

### GET /recommendations — Listar recomendaciones

```bash
curl -H "X-API-Key: snl_<key>" \
  "http://localhost:8001/recommendations?status=PENDING&limit=20"
```

### POST /recommendations/{id}/approve

```bash
curl -X POST -H "X-API-Key: snl_<key>" \
  "http://localhost:8001/recommendations/<id>/approve?note=Confirmado+por+SOC"
```

### POST /recommendations/{id}/reject

```bash
curl -X POST -H "X-API-Key: snl_<key>" \
  "http://localhost:8001/recommendations/<id>/reject?note=Falso+positivo"
```

### GET /audit/verify — Integridad del log

```bash
curl -H "X-API-Key: snl_<key>" http://localhost:8001/audit/verify
```

```json
{
  "status": "INTACT",
  "verified": true,
  "records_verified": 1543,
  "latest_hash": "a1b2c3d4..."
}
```

### GET /mlops/versions — Versiones del modelo

```bash
curl -H "X-API-Key: snl_<key>" http://localhost:8001/mlops/versions
```

### POST /mlops/retrain — Disparar reentrenamiento

```bash
curl -X POST -H "X-API-Key: snl_<key>" http://localhost:8001/mlops/retrain
```

---

## Gateway Universal SIEM

El Gateway conecta cualquier SIEM sin modificar su configuracion.

### 1. Registrar tu GRC

```bash
curl -X POST http://localhost:8001/gateway/register \
  -H "Content-Type: application/json" \
  -d '{
    "company_name": "Empresa ABC",
    "grc_url": "https://tu-grc.empresa.com",
    "grc_api_key": "tu-api-key-grc",
    "grc_api_secret": "tu-api-secret-grc"
  }'
```

Respuesta:
```json
{
  "sentinel_api_key": "snl_AbCdEf123...",
  "sentinel_api_secret": "secret-guardar-ahora",
  "webhook_url": "/gateway/analyze"
}
```

> Guarda `sentinel_api_secret` — solo se muestra una vez.

### 2. Enviar eventos al Gateway

```bash
curl -X POST http://localhost:8001/gateway/analyze \
  -H "X-API-Key: snl_AbCdEf123" \
  -H "Content-Type: application/json" \
  -d '{ ...evento-del-siem... }'
```

### Fuentes SIEM detectadas automaticamente

| SIEM | Criterio de deteccion |
|---|---|
| Wazuh | `"rule"` + `"agent"` |
| Microsoft Sentinel | `"Severity"` + `"IncidentNumber"` |
| Suricata | `"event_type"` + `"alert"` |
| Splunk | `"result"` o `"_raw"` |
| AWS CloudTrail | `"eventSource"` + `"awsRegion"` |
| IBM QRadar | `"sourceAddress"` + `"magnitude"` |
| Syslog / Firewall | `"message"` / `"SRC"` |
| Catch-all | Cualquier otro JSON |

### Patrones de ataque detectados

| Patron | Descripcion | Accion |
|---|---|---|
| `lateral_movement` | Auth fallida en activo A + exito en activo B, misma IP | `escalate` |
| `brute_force_success` | Multiples fallos + exito en mismo activo | `escalate` |
| `c2_beacon` | IP en lista negra AbuseIPDB | `escalate` |
| `brute_force` | 5+ fallos de auth en 6 minutos | `review` |
| `port_scan` | 10+ puertos distintos bloqueados | `review` |
| `suspicious_outbound` | Trafico saliente a destino inusual | `review` |

### Sandbox forense

Sube un archivo JSON/JSONL para analisis completo:

```bash
curl -X POST http://localhost:8001/gateway/sandbox \
  -F "file=@logs.json" \
  -F "allow_telemetry_training=true"
```

Recuperar resultado (TTL: 24h por privacidad):
```bash
curl http://localhost:8001/gateway/sandbox/<session_id>
```

---

## Dashboard de status

```
http://localhost:8001/dashboard
```

Muestra en tiempo real:
- Modo del modelo (DUMMY / SHADOW / LIVE)
- Estado del Circuit Breaker (CLOSED / HALF_OPEN / OPEN)
- Eventos normalizados hoy
- Recomendaciones PENDING / APPROVED / REJECTED
- Tabla con las 10 ultimas recomendaciones (score, asset, SHAP)
- Laboratorio Sandbox para subir y analizar archivos JSON

---

## Entrenar el modelo

### Con datos sinteticos (recomendado para empezar)

```bash
docker compose exec ml-api python -m app.models.trainer --mode synthetic
```

### Con datos historicos reales

```bash
docker compose exec ml-api python -m app.models.trainer --mode historical
```

> Requiere al menos 200 eventos en `normalized_features`.

### Dry run (ver metricas sin guardar)

```bash
docker compose exec ml-api python -m app.models.trainer --mode synthetic --dry-run
```

### Via API (reentrenamiento programatico)

```bash
curl -X POST -H "X-API-Key: snl_<key>" http://localhost:8001/mlops/retrain
```

Los artefactos se guardan en:
```
/app/model_artifacts/<version>/
    model.pkl        IsolationForest + StandardScaler
    model.sha256     hash de integridad SHA-256 (ISO 42001 S8.3)
```

El hash SHA-256 se verifica en cada carga. Si el artefacto fue manipulado, se rechaza.

---

## Simulador de ataques

```bash
cd simulator

# Escenarios disponibles
python attack_scenarios.py --scenario lateral_movement
python attack_scenarios.py --scenario brute_force
python attack_scenarios.py --scenario data_exfiltration
python attack_scenarios.py --scenario port_scan
python attack_scenarios.py --all

# Stress test
python stress-testing.py
```

Variables de entorno del simulador:
```env
SIM_CLIENT_ID=sim-client
SIM_CLIENT_SECRET=sim-secret-dev
```

---

## Circuit Breaker

Protege el sistema cuando el ML falla o detecta drift de datos.

```
CLOSED --[N fallos o PSI>0.2]--> OPEN --[timeout 60s]--> HALF_OPEN
  ^                                                           |
  +------------------[inferencia exitosa]---------------------+
```

| Estado | Comportamiento |
|---|---|
| `CLOSED` | Normal: usa el modelo ML |
| `OPEN` | HTTP 503: fallback sugerido a logica ISO 27005 |
| `HALF_OPEN` | Permite una inferencia de prueba |

Configurar en `.env`:
```env
CB_FAILURE_THRESHOLD=5    # fallos antes de abrir
CB_RECOVERY_TIMEOUT_S=60  # segundos antes de HALF_OPEN
```

Cerrar manualmente (emergencia):
```sql
UPDATE ml_circuit_breaker
SET state='CLOSED', failures=0, opened_at=NULL, updated_at=NOW();
```

---

## Verificacion de auditoria

El log usa una cadena SHA-256 donde cada registro firma al anterior.
Cualquier modificacion directa en la DB es detectable.

Eventos registrados automaticamente:

| Evento | Cuando |
|---|---|
| `INFERENCE` | Cada llamada a /infer |
| `INFERENCE_ERROR` | Cuando falla la inferencia |
| `RECOMMENDATION_APPROVED` | Al aprobar |
| `RECOMMENDATION_REJECTED` | Al rechazar |
| `ML_RETRAIN_SUCCESS` | Tras reentrenamiento exitoso |
| `ML_RETRAIN_ERROR` | Si falla el reentrenamiento |

---

## Variables de entorno

Todas las variables van en `.env`. Ninguna debe tener valores reales en el codigo.

| Variable | Descripcion | Requerido en prod |
|---|---|---|
| `DATABASE_URL` | URL de conexion PostgreSQL | Si |
| `REDIS_URL` | URL de conexion Redis | Si |
| `SECRET_KEY` | Secreto general (openssl rand -hex 32) | Si |
| `JWT_SECRET_KEY` | Secreto JWT (openssl rand -hex 64) | Si |
| `JWT_ALGORITHM` | Algoritmo JWT (default: HS256) | No |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Duracion access token (default: 60) | No |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Duracion refresh token (default: 7) | No |
| `CORS_ORIGINS` | Origenes CORS separados por coma | Si |
| `MODEL_MODE` | DUMMY / SHADOW / LIVE | Si |
| `MODEL_ARTIFACTS_PATH` | Ruta a artefactos del modelo | No |
| `DEV_GRC_URL` | URL del GRC destino | Si (modo LIVE) |
| `DEV_GRC_API_KEY` | API Key del GRC | Si (modo LIVE) |
| `DEV_GRC_API_SECRET` | API Secret del GRC | Si (modo LIVE) |
| `CB_FAILURE_THRESHOLD` | Fallos para abrir Circuit Breaker (default: 5) | No |
| `CB_RECOVERY_TIMEOUT_S` | Tiempo de recuperacion CB (default: 60) | No |
| `ABUSEIPDB_API_KEY` | API Key AbuseIPDB (dejar vacio para deshabilitar) | No |
| `KAFKA_BROKER_URL` | URL broker Kafka (vacio = usa Redis Queue) | No |
| `APP_ENV` | DEVELOPMENT / PRODUCTION | No |
| `LOG_LEVEL` | INFO / DEBUG / WARNING | No |

---

## Troubleshooting

### El servicio no arranca

```bash
# Ver logs de inicio
docker compose logs ml-api

# Verificar variables de entorno
docker compose exec ml-api env | grep -E "MODEL|DB|JWT"
```

### Error 401 / 403 en requests

- Para `/infer`, `/recommendations`, `/audit/verify`: usa `X-API-Key: <key>`
- Para endpoints auth (`/auth/register`, `/auth/login`): no requieren header
- Para endpoints de usuarios: usa `Authorization: Bearer <token>`

### El modelo no esta activo

```bash
# Ver estado del modelo
curl http://localhost:8001/health/model

# Entrenar si es necesario
docker compose exec ml-api python -m app.models.trainer --mode synthetic
```

### El Circuit Breaker esta OPEN

```bash
# Ver razon
docker compose logs ml-api | grep circuit

# Forzar cierre (con precaucion)
docker compose exec ml-db psql -U ml ml_features -c \
  "UPDATE ml_circuit_breaker SET state='CLOSED', failures=0, opened_at=NULL, updated_at=NOW();"
```

### El worker no procesa tareas

```bash
# Ver logs del worker
docker compose logs ml-worker

# Verificar que Redis esta activo
docker compose exec ml-redis redis-cli ping
```

### Ver migraciones pendientes

```bash
# Aplicar migracion manualmente
docker compose exec ml-db psql -U ml ml_features -f /migrations/003_risk_metrics.sql
```
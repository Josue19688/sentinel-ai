-- ============================================================
-- Sentinel ML - Feature Store Schema
-- PostgreSQL 15 + TimescaleDB
-- ============================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── Clientes HMAC registrados ────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_clients (
    id             SERIAL PRIMARY KEY,
    client_id      VARCHAR(64) UNIQUE NOT NULL,
    client_secret  VARCHAR(64) NOT NULL,  -- bcrypt hash del secreto (el valor original NUNCA se guarda)
    name           VARCHAR(255),
    active         BOOLEAN DEFAULT TRUE,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- ── Eventos normalizados del SIEM ────────────────────────────
CREATE TABLE IF NOT EXISTS normalized_features (
    id              BIGSERIAL,
    client_id       VARCHAR(64) NOT NULL,
    source_siem     VARCHAR(32) NOT NULL,  -- wazuh | sentinel | syslog
    asset_id        VARCHAR(128),
    timestamp_event TIMESTAMPTZ NOT NULL,
    severity_score  FLOAT NOT NULL,
    asset_value     FLOAT DEFAULT 0.5,
    event_type      VARCHAR(64),
    src_ip          VARCHAR(45),
    features_vector JSONB NOT NULL,
    pattern_hint    VARCHAR(50) DEFAULT 'none',
    raw_hash        VARCHAR(64),           -- SHA-256 del log original
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
);

SELECT create_hypertable('normalized_features', 'created_at',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE);

-- Retención automática: ventana móvil de 90 días
SELECT add_retention_policy('normalized_features',
    INTERVAL '90 days', if_not_exists => TRUE);

-- ── Recomendaciones de la IA ─────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_recommendations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       VARCHAR(255) NOT NULL,
    feature_id      BIGINT,
    asset_id        VARCHAR(255),
    anomaly_score   FLOAT NOT NULL,
    aro_suggested   FLOAT,
    confidence      VARCHAR(255),
    model_version   VARCHAR(255),
    model_mode      VARCHAR(64) DEFAULT 'DUMMY',  -- DUMMY | SHADOW | LIVE
    shap_values     JSONB,
    shap_ready      BOOLEAN DEFAULT FALSE,
    status          VARCHAR(64) DEFAULT 'PENDING', -- PENDING | APPROVED | REJECTED
    reviewed_by     VARCHAR(255),
    review_note     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at     TIMESTAMPTZ,

    -- Forensic & Network Data
    src_ip                   VARCHAR(64),
    pattern                  VARCHAR(255),
    event_type               VARCHAR(255),
    river_score              FLOAT,
    nmap_score               FLOAT,
    combined_score           FLOAT,
    river_warmup             BOOLEAN,
    lateral_movement_detected BOOLEAN DEFAULT FALSE,

    -- ISO 27005 / Risk Engineering
    ef                       FLOAT,
    sle                      FLOAT,
    aro                      FLOAT,
    ale                      FLOAT,
    aro_sample_size          INTEGER,
    aro_period_days          INTEGER,
    aro_confidence           VARCHAR(255),

    -- Asset Snapshot
    valor_activo_snapshot    FLOAT,
    clasificacion_criticidad VARCHAR(255),
    cia_snapshot             JSONB,
    impacted_dimensions      JSONB,
    data_flags               JSONB,

    -- Historical & Pattern Analysis
    attack_count_historical  INTEGER,
    first_occurrence_pattern TIMESTAMPTZ,
    recurrence_flag          BOOLEAN
);

-- ── AuditLog con Hash Chain (ISO 27001 A.12.4.2) ────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGSERIAL PRIMARY KEY,
    event_type    VARCHAR(64) NOT NULL,
    entity_id     VARCHAR(128),
    actor         VARCHAR(128),
    payload       JSONB,
    previous_hash VARCHAR(64),            -- SHA-256 del registro anterior
    current_hash  VARCHAR(64) NOT NULL,   -- SHA-256(id||payload||previous_hash)
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── Circuit Breaker del ML Service ──────────────────────────
CREATE TABLE IF NOT EXISTS ml_circuit_breaker (
    id          SERIAL PRIMARY KEY,
    state       VARCHAR(16) DEFAULT 'CLOSED',  -- CLOSED | OPEN | HALF_OPEN
    failures    INTEGER DEFAULT 0,
    last_fail   TIMESTAMPTZ,
    opened_at   TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO ml_circuit_breaker (state) VALUES ('CLOSED')
    ON CONFLICT DO NOTHING;

-- ── Registro de modelos (MLflow alternativo ligero) ──────────
CREATE TABLE IF NOT EXISTS model_registry (
    id            SERIAL PRIMARY KEY,
    version       VARCHAR(32) NOT NULL,
    algorithm     VARCHAR(64) DEFAULT 'IsolationForest',
    psi_score     FLOAT,
    f1_score      FLOAT,
    trained_at    TIMESTAMPTZ DEFAULT NOW(),
    is_active     BOOLEAN DEFAULT FALSE,
    artifact_path VARCHAR(512)
);

-- ── Índices de performance ───────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_features_client ON normalized_features(client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_features_asset  ON normalized_features(asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reco_status     ON ml_recommendations(status, client_id);
CREATE INDEX IF NOT EXISTS idx_audit_entity    ON audit_log(entity_id, created_at DESC);



-- ── Clientes del Gateway (registro de GRCs) ──────────────────
CREATE TABLE IF NOT EXISTS sentinel_clients (
    id             SERIAL PRIMARY KEY,
    sentinel_key   VARCHAR(64) UNIQUE NOT NULL,
    secret_hash    VARCHAR(64) NOT NULL,
    secret_salt    VARCHAR(32) NOT NULL DEFAULT '',  -- salt único por cliente (H-05)
    company_name   VARCHAR(255) NOT NULL,
    grc_url        VARCHAR(512),
    grc_api_key    VARCHAR(128),
    grc_api_secret VARCHAR(128),
    active         BOOLEAN DEFAULT TRUE,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- -- Inventario de Activos (ISO 27005) -------------------------
CREATE TABLE IF NOT EXISTS assets (
    id              SERIAL PRIMARY KEY,
    client_id       VARCHAR(64) NOT NULL,  -- sentinel_key vinculada

    -- Identidad tecnica
    nombre_activo   VARCHAR(255) NOT NULL,
    tipo_activo     VARCHAR(100),
    hostname        VARCHAR(255),
    ip_address      VARCHAR(50),
    mac_address     VARCHAR(50),
    technical_id    VARCHAR(100),

    -- Organizacional
    propietario     VARCHAR(100),
    custodio        VARCHAR(100),
    administrador   VARCHAR(100),
    propietario_informacion VARCHAR(100),
    ubicacion       VARCHAR(255),
    departamento    VARCHAR(100),
    descripcion     TEXT,
    observaciones   TEXT,
    estado_parcheo  VARCHAR(100),
    clasificacion_criticidad VARCHAR(20), -- Bajo|Medio|Alto|Critico

    -- Financiero y CIA (ISO 27005)
    valor_activo           NUMERIC(20, 2) DEFAULT 0.0,
    valor_confidencialidad INTEGER DEFAULT 3 CHECK (valor_confidencialidad BETWEEN 1 AND 5),
    valor_integridad       INTEGER DEFAULT 3 CHECK (valor_integridad BETWEEN 1 AND 5),
    valor_disponibilidad   INTEGER DEFAULT 3 CHECK (valor_disponibilidad BETWEEN 1 AND 5),

    -- Flags sensibilidad
    contiene_pii    BOOLEAN DEFAULT FALSE,
    contiene_pci    BOOLEAN DEFAULT FALSE,
    contiene_phi    BOOLEAN DEFAULT FALSE,
    contiene_pfi    BOOLEAN DEFAULT FALSE,

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Indices de busqueda para correlacion SIEM
CREATE INDEX IF NOT EXISTS idx_assets_client_id  ON assets(client_id);
CREATE INDEX IF NOT EXISTS idx_assets_hostname   ON assets(client_id, hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip_address ON assets(client_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_tech_id    ON assets(client_id, technical_id);
-- Migration 001: Identidad de Usuarios (JWT + Dashboard)
-- Ejecutar: psql $DATABASE_URL -f migrations/001_auth_users.sql

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'auditor');

CREATE TABLE IF NOT EXISTS auth_users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT        NOT NULL UNIQUE,
    hashed_password TEXT        NOT NULL,
    role            user_role   NOT NULL DEFAULT 'analyst',
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    -- version se incrementa en cambio de password o revocaciÃ³n masiva.
    -- El JWT lleva este nÃºmero; si no coincide, el token es invÃ¡lido.
    version         INTEGER     NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_users_email   ON auth_users (email);
CREATE INDEX idx_auth_users_active  ON auth_users (is_active) WHERE is_active = TRUE;

-- Actualiza updated_at automÃ¡ticamente en cada UPDATE
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_auth_users_updated_at
    BEFORE UPDATE ON auth_users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- Migration 002: API Keys para integraciÃ³n SIEM / Machine Identity
-- Ejecutar: psql $DATABASE_URL -f migrations/002_auth_api_keys.sql
-- Depende de: 001_auth_users.sql

CREATE TABLE IF NOT EXISTS auth_api_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    -- Primeros 8 chars de la key en claro: permite lookup sin exponer el secret.
    -- Ejemplo: "snl_a1b2" â†’ busca por prefix, luego verifica bcrypt del resto.
    key_prefix  TEXT        NOT NULL UNIQUE,
    secret_hash TEXT        NOT NULL,   -- bcrypt del secret completo
    name        TEXT        NOT NULL,   -- Label legible: "Wazuh ProducciÃ³n"
    scopes      JSONB       NOT NULL DEFAULT '[]',
    expires_at  TIMESTAMPTZ,            -- NULL = no expira
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id   ON auth_api_keys (user_id);
CREATE INDEX idx_api_keys_prefix    ON auth_api_keys (key_prefix);
CREATE INDEX idx_api_keys_active    ON auth_api_keys (is_active) WHERE is_active = TRUE;
-- Fase 2: Tabla de historial de mÃ©tricas de riesgo por activo
-- Persiste cada cÃ¡lculo de ARO/ALE para anÃ¡lisis temporal (YoY, tendencias)
-- Permite al GRC ver cÃ³mo evolucionÃ³ el riesgo de un activo a lo largo del tiempo

CREATE TABLE IF NOT EXISTS risk_metrics (
    id              BIGSERIAL PRIMARY KEY,
    client_id       VARCHAR(64)  NOT NULL,
    asset_id        VARCHAR(128) NOT NULL,
    risk_scenario   VARCHAR(64)  NOT NULL,  -- brute_force, lateral_movement, etc.
    window_days     INTEGER      NOT NULL DEFAULT 30,

    -- Conteo real de incidencias en la ventana temporal
    incident_count  INTEGER      NOT NULL DEFAULT 0,

    -- MÃ©tricas de riesgo cuantitativo
    calculated_aro  NUMERIC(12, 4) NOT NULL DEFAULT 0,  -- Annual Rate of Occurrence
    exposure_factor NUMERIC(5, 4)  NOT NULL DEFAULT 0,  -- 0.0 - 1.0
    ale_delta       NUMERIC(15, 2) NOT NULL DEFAULT 0,  -- Incremento en pÃ©rdida anual estimada

    -- Control ISO 27001 fallido detectado
    failed_control_id VARCHAR(20),  -- Ej: A.9.4.2, A.10.1.1

    -- Trazabilidad y auditorÃ­a
    evidence_hash   VARCHAR(64),    -- SHA-256 del payload que generÃ³ este registro
    audit_chain_v   INTEGER,        -- PosiciÃ³n en el Hash Chain del GRC

    -- Timestamps
    calculated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_start    TIMESTAMPTZ,
    window_end      TIMESTAMPTZ
);

-- Ãndices para consultas del motor de riesgo
CREATE INDEX IF NOT EXISTS idx_risk_metrics_asset ON risk_metrics (asset_id, calculated_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_metrics_client ON risk_metrics (client_id, calculated_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_metrics_scenario ON risk_metrics (risk_scenario, calculated_at DESC);

-- Vista: tendencia anual de ARO por activo (para el dashboard del GRC)
CREATE OR REPLACE VIEW v_aro_trend AS
SELECT
    client_id,
    asset_id,
    risk_scenario,
    DATE_TRUNC('month', calculated_at) AS month,
    AVG(calculated_aro)::NUMERIC(12,4) AS avg_aro,
    MAX(calculated_aro)::NUMERIC(12,4) AS max_aro,
    SUM(incident_count)                AS total_incidents,
    AVG(ale_delta)::NUMERIC(15,2)      AS avg_ale_delta
FROM risk_metrics
GROUP BY client_id, asset_id, risk_scenario, DATE_TRUNC('month', calculated_at)
ORDER BY month DESC;

COMMENT ON TABLE risk_metrics IS
    'Historial de mÃ©tricas de riesgo cuantitativo (ARO/ALE/EF) por activo. '
    'Alimenta el GRC para cÃ¡lculos financieros y reportes de cumplimiento ISO 27001/27005.';
INSERT INTO auth_users (email, hashed_password, role) VALUES ('josue@sentinel.ai', '$2b$12$BKRPj5BpQTMeh.gX70qY1eRR2Dh8w56R6jyEE9NV2Le381O2nRvm.', 'admin');

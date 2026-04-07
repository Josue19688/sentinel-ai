-- ============================================================
-- Sentinel ML - Feature Store Schema
-- PostgreSQL 15 + TimescaleDB
-- ============================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── Clientes HMAC registrados ────────────────────────────────
CREATE TABLE IF NOT EXISTS ml_clients (
    id             SERIAL PRIMARY KEY,
    client_id      VARCHAR(64) UNIQUE NOT NULL,
    client_secret  VARCHAR(64) NOT NULL,  -- secret real para HMAC-SHA256 (bcrypt es incompatible con HMAC)
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
    client_id       VARCHAR(64) NOT NULL,
    feature_id      BIGINT,
    asset_id        VARCHAR(128),
    anomaly_score   FLOAT NOT NULL,
    aro_suggested   FLOAT,
    confidence      FLOAT,
    model_version   VARCHAR(32),
    model_mode      VARCHAR(16) DEFAULT 'DUMMY',  -- DUMMY | SHADOW | LIVE
    shap_values     JSONB,
    shap_ready      BOOLEAN DEFAULT FALSE,
    status          VARCHAR(16) DEFAULT 'PENDING', -- PENDING | APPROVED | REJECTED
    reviewed_by     VARCHAR(128),
    review_note     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at     TIMESTAMPTZ
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

-- ── Cliente de demo para pruebas locales ─────────────────────
INSERT INTO ml_clients (client_id, client_secret, name)
VALUES (
    'sim-client',
    'sim-secret-dev',   -- SECRET DE DEMO — cambiar en producción
    'Simulator - Demo Local'
) ON CONFLICT (client_id) DO NOTHING;

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

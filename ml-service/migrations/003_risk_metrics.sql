-- Fase 2: Tabla de historial de métricas de riesgo por activo
-- Persiste cada cálculo de ARO/ALE para análisis temporal (YoY, tendencias)
-- Permite al GRC ver cómo evolucionó el riesgo de un activo a lo largo del tiempo

CREATE TABLE IF NOT EXISTS risk_metrics (
    id              BIGSERIAL PRIMARY KEY,
    client_id       VARCHAR(64)  NOT NULL,
    asset_id        VARCHAR(128) NOT NULL,
    risk_scenario   VARCHAR(64)  NOT NULL,  -- brute_force, lateral_movement, etc.
    window_days     INTEGER      NOT NULL DEFAULT 30,

    -- Conteo real de incidencias en la ventana temporal
    incident_count  INTEGER      NOT NULL DEFAULT 0,

    -- Métricas de riesgo cuantitativo
    calculated_aro  NUMERIC(12, 4) NOT NULL DEFAULT 0,  -- Annual Rate of Occurrence
    exposure_factor NUMERIC(5, 4)  NOT NULL DEFAULT 0,  -- 0.0 - 1.0
    ale_delta       NUMERIC(15, 2) NOT NULL DEFAULT 0,  -- Incremento en pérdida anual estimada

    -- Control ISO 27001 fallido detectado
    failed_control_id VARCHAR(20),  -- Ej: A.9.4.2, A.10.1.1

    -- Trazabilidad y auditoría
    evidence_hash   VARCHAR(64),    -- SHA-256 del payload que generó este registro
    audit_chain_v   INTEGER,        -- Posición en el Hash Chain del GRC

    -- Timestamps
    calculated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_start    TIMESTAMPTZ,
    window_end      TIMESTAMPTZ
);

-- Índices para consultas del motor de riesgo
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
    'Historial de métricas de riesgo cuantitativo (ARO/ALE/EF) por activo. '
    'Alimenta el GRC para cálculos financieros y reportes de cumplimiento ISO 27001/27005.';

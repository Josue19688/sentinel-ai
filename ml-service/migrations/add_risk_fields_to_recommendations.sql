-- ============================================================
-- Migration: enriquecer ml_recommendations para análisis de
-- riesgo ISO 27005 completo y comportamiento futuro de activos.
--
-- Ejecutar con:
--   psql $DATABASE_URL -f migrations/add_risk_fields_to_recommendations.sql
--
-- Idempotente: usa IF NOT EXISTS y ADD COLUMN IF NOT EXISTS.
-- ============================================================

BEGIN;

-- ── 1. IP atacante ────────────────────────────────────────────────────────────
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS src_ip VARCHAR(50);

-- ── 2. Patrón y tipo de evento ────────────────────────────────────────────────
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS pattern         VARCHAR(100),
    ADD COLUMN IF NOT EXISTS event_type      VARCHAR(200);

-- ── 3. Scores ML completos (foto del momento) ────────────────────────────────
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS river_score     NUMERIC(6,4) DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS nmap_score      NUMERIC(6,4) DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS combined_score  NUMERIC(6,4) DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS river_warmup    BOOLEAN      DEFAULT FALSE;

-- ── 4. Cálculos ISO 27005 ────────────────────────────────────────────────────
--      ef    = Exposure Factor (fracción del activo perdida)
--      sle   = Single Loss Expectancy = valor_activo × ef
--      aro   = Annualized Rate of Occurrence (desde historial real)
--      ale   = Annualized Loss Expectancy = sle × aro
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS ef              NUMERIC(6,4),
    ADD COLUMN IF NOT EXISTS sle             NUMERIC(20,2),
    ADD COLUMN IF NOT EXISTS aro             NUMERIC(10,4),
    ADD COLUMN IF NOT EXISTS ale             NUMERIC(20,2);

-- ── 5. Metadatos de confianza del cálculo ARO ────────────────────────────────
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS aro_sample_size  INTEGER,      -- eventos usados para calcular ARO
    ADD COLUMN IF NOT EXISTS aro_period_days  INTEGER,      -- ventana de observación en días
    ADD COLUMN IF NOT EXISTS aro_confidence   VARCHAR(30);  -- high / medium / low / insufficient_data

-- ── 6. Snapshot del activo en el momento del incidente ───────────────────────
--      Guardamos snapshot porque valor_activo puede cambiar después.
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS valor_activo_snapshot    NUMERIC(20,2),
    ADD COLUMN IF NOT EXISTS clasificacion_criticidad VARCHAR(20),
    ADD COLUMN IF NOT EXISTS cia_snapshot             JSONB,
    -- Ejemplo cia_snapshot:
    -- {"confidencialidad": 4, "integridad": 3, "disponibilidad": 5}
    ADD COLUMN IF NOT EXISTS impacted_dimensions      JSONB,
    -- Ejemplo impacted_dimensions:
    -- {"confidencialidad": 4, "disponibilidad": 5}
    -- Solo las dimensiones que impacta el patrón detectado.
    ADD COLUMN IF NOT EXISTS data_flags               JSONB;
    -- Ejemplo data_flags:
    -- {"pii": true, "pci": false, "phi": false, "pfi": false}

-- ── 7. Contexto histórico para tendencias futuras ────────────────────────────
ALTER TABLE ml_recommendations
    ADD COLUMN IF NOT EXISTS attack_count_historical  INTEGER DEFAULT 0,
    -- Cuántos eventos de ataque registrados para este activo antes de este incidente.
    ADD COLUMN IF NOT EXISTS first_occurrence_pattern BOOLEAN DEFAULT FALSE,
    -- TRUE si es la primera vez que se detecta este patrón en este activo.
    ADD COLUMN IF NOT EXISTS recurrence_flag          BOOLEAN DEFAULT FALSE;
    -- TRUE si el mismo patrón ya ocurrió antes en este activo.

-- ── 8. Índices para consultas de tendencias ──────────────────────────────────
CREATE INDEX IF NOT EXISTS ix_mlrec_asset_pattern
    ON ml_recommendations (asset_id, pattern, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_mlrec_client_created
    ON ml_recommendations (client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_mlrec_src_ip
    ON ml_recommendations (src_ip, created_at DESC);

COMMIT;

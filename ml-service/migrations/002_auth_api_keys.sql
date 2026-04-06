-- Migration 002: API Keys para integración SIEM / Machine Identity
-- Ejecutar: psql $DATABASE_URL -f migrations/002_auth_api_keys.sql
-- Depende de: 001_auth_users.sql

CREATE TABLE IF NOT EXISTS auth_api_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    -- Primeros 8 chars de la key en claro: permite lookup sin exponer el secret.
    -- Ejemplo: "snl_a1b2" → busca por prefix, luego verifica bcrypt del resto.
    key_prefix  TEXT        NOT NULL UNIQUE,
    secret_hash TEXT        NOT NULL,   -- bcrypt del secret completo
    name        TEXT        NOT NULL,   -- Label legible: "Wazuh Producción"
    scopes      JSONB       NOT NULL DEFAULT '[]',
    expires_at  TIMESTAMPTZ,            -- NULL = no expira
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id   ON auth_api_keys (user_id);
CREATE INDEX idx_api_keys_prefix    ON auth_api_keys (key_prefix);
CREATE INDEX idx_api_keys_active    ON auth_api_keys (is_active) WHERE is_active = TRUE;

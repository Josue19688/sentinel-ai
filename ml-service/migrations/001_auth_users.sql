-- Migration 001: Identidad de Usuarios (JWT + Dashboard)
-- Ejecutar: psql $DATABASE_URL -f migrations/001_auth_users.sql

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'auditor');

CREATE TABLE IF NOT EXISTS auth_users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT        NOT NULL UNIQUE,
    hashed_password TEXT        NOT NULL,
    role            user_role   NOT NULL DEFAULT 'analyst',
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    -- version se incrementa en cambio de password o revocación masiva.
    -- El JWT lleva este número; si no coincide, el token es inválido.
    version         INTEGER     NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_users_email   ON auth_users (email);
CREATE INDEX idx_auth_users_active  ON auth_users (is_active) WHERE is_active = TRUE;

-- Actualiza updated_at automáticamente en cada UPDATE
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

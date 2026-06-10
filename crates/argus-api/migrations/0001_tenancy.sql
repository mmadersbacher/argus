-- Multi-tenant foundation: tenants, users, API keys, tenant-scoped assets,
-- and an audit trail. Replaces the pre-migration single-tenant `assets`
-- table (auto-created, demo-only data) — dropped here intentionally.

DROP TABLE IF EXISTS assets;

CREATE TABLE tenants (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX users_tenant_idx ON users (tenant_id);

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    -- SHA-256 hex of the secret; the plaintext is shown once at creation.
    key_hash     TEXT NOT NULL UNIQUE,
    role         TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX api_keys_tenant_idx ON api_keys (tenant_id);

CREATE TABLE assets (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dedup_key  TEXT NOT NULL,
    body       JSONB NOT NULL,
    risk       REAL NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dedup_key)
);

CREATE INDEX assets_tenant_risk_idx ON assets (tenant_id, risk DESC);

CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Keep the audit row if the acting user is removed; just null the actor.
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    detail     JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_tenant_idx ON audit_log (tenant_id, created_at DESC);

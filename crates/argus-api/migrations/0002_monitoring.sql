-- Continuous monitoring: change events emitted by scans, and per-tenant
-- monitor configuration for the background scheduler.

CREATE TABLE events (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Correlation key of the affected asset (survives asset re-discovery).
    dedup_key  TEXT NOT NULL,
    -- Display name snapshot at event time (hostname > IP > short asset id).
    asset_name TEXT NOT NULL,
    kind       TEXT NOT NULL,
    detail     JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX events_tenant_created_idx ON events (tenant_id, created_at DESC);

-- One monitor per tenant (deliberate v1 simplification: the tenant_id PK
-- makes "the monitor" unambiguous and the upsert trivial).
CREATE TABLE monitors (
    tenant_id        UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    target           TEXT NOT NULL,
    interval_minutes INT NOT NULL CHECK (interval_minutes BETWEEN 1 AND 1440),
    enabled          BOOLEAN NOT NULL DEFAULT true,
    deep             BOOLEAN NOT NULL DEFAULT false,
    last_run_at      TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

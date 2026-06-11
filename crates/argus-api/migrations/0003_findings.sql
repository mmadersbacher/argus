-- Finding triage (IR workflow v1): analyst-set lifecycle status per
-- (asset, CVE). A finding without a row is open. Keyed by the stable asset
-- id (carried forward across re-scans) + CVE id, so triage decisions survive
-- the per-scan re-derivation of the vulnerability lists. Status is triage
-- metadata only — it does not alter the computed risk score.
CREATE TABLE finding_status (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id   UUID NOT NULL,
    cve_id     TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('acknowledged', 'resolved', 'false_positive')),
    note       TEXT NOT NULL DEFAULT '',
    -- Login email, or 'api-key' for machine callers (snapshot, not a FK —
    -- the decision trail must survive user deletion).
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id, cve_id)
);

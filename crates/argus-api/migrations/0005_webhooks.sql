-- Per-tenant outbound webhook for change-event delivery.
--
-- One webhook per tenant (tenant_id PK). `secret` is the HMAC-SHA256 signing
-- key the receiver uses to verify the `x-argus-signature` header. Deleting the
-- tenant removes its webhook.
CREATE TABLE tenant_webhooks (
    tenant_id  UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    url        TEXT        NOT NULL,
    secret     TEXT        NOT NULL,
    enabled    BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

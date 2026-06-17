//! Postgres store (sqlx): tenants, users, API keys, audit log, and the
//! tenant-scoped asset inventory.
//!
//! Schema is owned by the embedded sqlx migrations (`migrations/`). Every
//! asset query takes a `tenant_id` — there is deliberately no unscoped
//! variant, so cross-tenant leaks cannot be written by accident.

use argus_core::tenant::Role;
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::seed::ScoredAsset;

/// Connect, build the pool, and run pending migrations.
pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

// ---------------------------------------------------------------------------
// Tenants & users
// ---------------------------------------------------------------------------

/// A user row as needed for login and admin listings.
#[derive(Debug)]
pub struct UserRow {
    /// Stable identifier.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Login email (globally unique).
    pub email: String,
    /// Argon2 PHC string.
    pub password_hash: String,
    /// Access role.
    pub role: Role,
}

/// Number of tenants (used to detect first run for bootstrapping).
pub async fn tenant_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Whether a tenant slug is already taken (pre-check for signup).
pub async fn tenant_slug_exists(pool: &PgPool, slug: &str) -> Result<bool, sqlx::Error> {
    let (exists,): (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)")
        .bind(slug)
        .fetch_one(pool)
        .await?;
    Ok(exists)
}

/// Whether a login email is already registered (pre-check for signup).
pub async fn user_email_exists(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let (exists,): (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(email)
        .fetch_one(pool)
        .await?;
    Ok(exists)
}

/// Create a tenant. Fails on duplicate slug. Takes any executor so it can
/// run inside the signup transaction.
pub async fn create_tenant<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
    name: &str,
    slug: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(name)
        .bind(slug)
        .execute(executor)
        .await?;
    Ok(())
}

/// Create a user. Fails on duplicate email. Takes any executor so it can
/// run inside the signup transaction.
pub async fn create_user<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    user: &UserRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, role)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user.id)
    .bind(user.tenant_id)
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(user.role.as_str())
    .execute(executor)
    .await?;
    Ok(())
}

/// Look up a user by login email (for authentication; not tenant-scoped
/// because the email is globally unique and determines the tenant).
pub async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let row: Option<(Uuid, Uuid, String, String, String)> = sqlx::query_as(
        "SELECT id, tenant_id, email, password_hash, role FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(id, tenant_id, email, password_hash, role)| {
        Some(UserRow {
            id,
            tenant_id,
            email,
            password_hash,
            role: Role::parse(&role)?,
        })
    }))
}

/// List the users of one tenant: `(id, email, role)`.
pub async fn list_users(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<(Uuid, String, Role)>, sqlx::Error> {
    let rows: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, email, role FROM users WHERE tenant_id = $1 ORDER BY email")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, email, role)| Some((id, email, Role::parse(&role)?)))
        .collect())
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

/// An API key match: the tenant and role the key grants.
#[derive(Debug)]
pub struct ApiKeyRow {
    /// Tenant the key is scoped to.
    pub tenant_id: Uuid,
    /// Role the key grants.
    pub role: Role,
}

/// Store a new API key (hash only; plaintext never touches the database).
pub async fn create_api_key(
    pool: &PgPool,
    id: Uuid,
    tenant_id: Uuid,
    name: &str,
    key_hash: &str,
    role: Role,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_hash, role)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(name)
    .bind(key_hash)
    .bind(role.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolve an API key by hash and stamp its `last_used_at`.
pub async fn find_api_key(pool: &PgPool, key_hash: &str) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1
         RETURNING tenant_id, role",
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(tenant_id, role)| {
        Some(ApiKeyRow {
            tenant_id,
            role: Role::parse(&role)?,
        })
    }))
}

/// List a tenant's API keys: `(id, name, role)`. Hashes are never returned.
pub async fn list_api_keys(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<(Uuid, String, Role)>, sqlx::Error> {
    let rows: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, name, role FROM api_keys WHERE tenant_id = $1 ORDER BY name")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, name, role)| Some((id, name, Role::parse(&role)?)))
        .collect())
}

/// Delete one of the tenant's API keys; returns whether a key was removed.
pub async fn delete_api_key(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// Append an audit entry. Best-effort: failures are logged, never fatal.
pub async fn audit(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    action: &str,
    detail: serde_json::Value,
) {
    let result = sqlx::query(
        "INSERT INTO audit_log (tenant_id, user_id, action, detail) VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(action)
    .bind(detail)
    .execute(pool)
    .await;
    if let Err(err) = result {
        tracing::error!(error = %err, action, "audit log write failed");
    }
}

// ---------------------------------------------------------------------------
// Asset inventory (tenant-scoped)
// ---------------------------------------------------------------------------

/// Insert or update an asset by its correlation key (dedup on repeated scans).
pub async fn upsert(
    pool: &PgPool,
    tenant_id: Uuid,
    asset: &ScoredAsset,
) -> Result<(), sqlx::Error> {
    let body = serde_json::to_value(asset).expect("ScoredAsset serializes");
    sqlx::query(
        "INSERT INTO assets (tenant_id, dedup_key, body, risk, updated_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (tenant_id, dedup_key)
         DO UPDATE SET body = EXCLUDED.body, risk = EXCLUDED.risk, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(asset.asset.dedup_key())
    .bind(body)
    .bind(asset.risk.value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically upsert one asset and record its change events in a single
/// transaction, so the diff baseline (the stored asset) never advances without
/// its events also being persisted. Either everything commits or nothing does.
pub async fn commit_asset(
    pool: &PgPool,
    tenant_id: Uuid,
    asset: &ScoredAsset,
    events: &[(&str, &serde_json::Value)],
    dedup_key: &str,
    asset_name: &str,
) -> Result<(), sqlx::Error> {
    let body = serde_json::to_value(asset).expect("ScoredAsset serializes");
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO assets (tenant_id, dedup_key, body, risk, updated_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (tenant_id, dedup_key)
         DO UPDATE SET body = EXCLUDED.body, risk = EXCLUDED.risk, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(dedup_key)
    .bind(body)
    .bind(asset.risk.value)
    .execute(&mut *tx)
    .await?;
    for (kind, detail) in events {
        sqlx::query(
            "INSERT INTO events (tenant_id, dedup_key, asset_name, kind, detail)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant_id)
        .bind(dedup_key)
        .bind(asset_name)
        .bind(*kind)
        .bind(*detail)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Load one tenant's full inventory, highest risk first.
pub async fn load_all(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<ScoredAsset>, sqlx::Error> {
    let rows: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT body FROM assets WHERE tenant_id = $1 ORDER BY risk DESC")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(body,)| match serde_json::from_value(body) {
            Ok(asset) => Some(asset),
            Err(e) => {
                // A row that no longer decodes (e.g. after a schema change) is
                // skipped — but loudly, so the data-integrity drift is visible
                // rather than a silently vanishing asset.
                tracing::warn!(%tenant_id, error = %e, "skipping asset row that failed to deserialize");
                None
            }
        })
        .collect())
}

/// Load a single asset by its correlation key, if present.
pub async fn load_one(
    pool: &PgPool,
    tenant_id: Uuid,
    dedup_key: &str,
) -> Result<Option<ScoredAsset>, sqlx::Error> {
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT body FROM assets WHERE tenant_id = $1 AND dedup_key = $2")
            .bind(tenant_id)
            .bind(dedup_key)
            .fetch_optional(pool)
            .await?;
    match row {
        None => Ok(None),
        Some((body,)) => match serde_json::from_value(body) {
            Ok(asset) => Ok(Some(asset)),
            Err(e) => {
                // Corrupted reads as absent (callers treat it as not-found),
                // but log so re-minting an asset's identity is not silent.
                tracing::warn!(%tenant_id, dedup_key, error = %e, "asset row failed to deserialize; treating as absent");
                Ok(None)
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Change events & monitors (continuous monitoring)
// ---------------------------------------------------------------------------

/// A change event as returned by `GET /api/events`.
#[derive(Debug, Serialize)]
pub struct EventRow {
    /// Monotonic event id.
    pub id: i64,
    /// Event kind (`asset.new`, `services.changed`, `vulns.changed`, `risk.changed`).
    pub kind: String,
    /// Correlation key of the affected asset.
    pub dedup_key: String,
    /// Display name of the affected asset at event time.
    pub asset_name: String,
    /// Kind-specific payload.
    pub detail: serde_json::Value,
    /// When the event was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A tenant's monitor configuration.
#[derive(Debug)]
pub struct MonitorRow {
    /// Scan target spec (ip / cidr / range).
    pub target: String,
    /// Scan cadence in minutes, `1..=1440`.
    pub interval_minutes: i32,
    /// Whether scheduled scans run.
    pub enabled: bool,
    /// Whether scheduled scans use the privileged deep engine.
    pub deep: bool,
    /// When the monitor last started a run (`None` until the first run).
    pub last_run_at: Option<OffsetDateTime>,
}

/// A monitor claimed for an immediate scheduled run.
#[derive(Debug)]
pub struct DueMonitor {
    /// Tenant the run is scoped to.
    pub tenant_id: Uuid,
    /// Scan target spec.
    pub target: String,
    /// Whether to use the privileged deep engine.
    pub deep: bool,
}

/// Record one change event for an asset.
pub async fn record_event(
    pool: &PgPool,
    tenant_id: Uuid,
    dedup_key: &str,
    asset_name: &str,
    kind: &str,
    detail: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO events (tenant_id, dedup_key, asset_name, kind, detail)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant_id)
    .bind(dedup_key)
    .bind(asset_name)
    .bind(kind)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete change events older than `retention_days`; returns how many rows
/// were removed. Keeps the unbounded-growth `events` table from filling up.
pub async fn prune_events(pool: &PgPool, retention_days: i64) -> Result<u64, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM events WHERE created_at < now() - make_interval(days => $1)")
            .bind(retention_days)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// List a tenant's most recent change events, newest first.
pub async fn list_events(
    pool: &PgPool,
    tenant_id: Uuid,
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    let rows: Vec<(
        i64,
        String,
        String,
        String,
        serde_json::Value,
        OffsetDateTime,
    )> = sqlx::query_as(
        "SELECT id, kind, dedup_key, asset_name, detail, created_at
         FROM events WHERE tenant_id = $1
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, kind, dedup_key, asset_name, detail, created_at)| EventRow {
                id,
                kind,
                dedup_key,
                asset_name,
                detail,
                created_at,
            },
        )
        .collect())
}

/// Fetch a tenant's monitor configuration, if one was ever saved.
pub async fn get_monitor(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<MonitorRow>, sqlx::Error> {
    let row: Option<(String, i32, bool, bool, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT target, interval_minutes, enabled, deep, last_run_at
         FROM monitors WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(target, interval_minutes, enabled, deep, last_run_at)| MonitorRow {
            target,
            interval_minutes,
            enabled,
            deep,
            last_run_at,
        },
    ))
}

/// Create or replace a tenant's monitor configuration (`last_run_at` is kept).
pub async fn set_monitor(
    pool: &PgPool,
    tenant_id: Uuid,
    target: &str,
    interval_minutes: i32,
    enabled: bool,
    deep: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO monitors (tenant_id, target, interval_minutes, enabled, deep, updated_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (tenant_id)
         DO UPDATE SET target = EXCLUDED.target,
                       interval_minutes = EXCLUDED.interval_minutes,
                       enabled = EXCLUDED.enabled,
                       deep = EXCLUDED.deep,
                       updated_at = now()",
    )
    .bind(tenant_id)
    .bind(target)
    .bind(interval_minutes)
    .bind(enabled)
    .bind(deep)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically claim every monitor that is due for a run.
///
/// Stamping `last_run_at` in the same statement that selects the due rows
/// means a monitor is claimed at most once per interval, even with multiple
/// scheduler instances — the claim happens *before* the (slow) scan.
pub async fn claim_due_monitors(pool: &PgPool) -> Result<Vec<DueMonitor>, sqlx::Error> {
    let rows: Vec<(Uuid, String, bool)> = sqlx::query_as(
        "UPDATE monitors SET last_run_at = now()
         WHERE enabled
           AND (last_run_at IS NULL
                OR last_run_at + make_interval(mins => interval_minutes) <= now())
         RETURNING tenant_id, target, deep",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(tenant_id, target, deep)| DueMonitor {
            tenant_id,
            target,
            deep,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Finding triage (IR workflow)
// ---------------------------------------------------------------------------

/// One triage decision: the analyst-set status of a (asset, CVE) finding.
/// Findings without a row are open.
#[derive(Debug, Clone, Serialize)]
pub struct FindingStatusRow {
    /// Asset the finding belongs to.
    pub asset_id: Uuid,
    /// CVE identifier.
    pub cve_id: String,
    /// `acknowledged`, `resolved` or `false_positive`.
    pub status: String,
    /// Free-text analyst note (may be empty).
    pub note: String,
    /// Who set the status (login email, or `api-key`).
    pub updated_by: String,
    /// When the status was last set.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Every triage decision of a tenant.
pub async fn list_finding_statuses(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<FindingStatusRow>, sqlx::Error> {
    let rows: Vec<(Uuid, String, String, String, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT asset_id, cve_id, status, note, updated_by, updated_at
         FROM finding_status WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(asset_id, cve_id, status, note, updated_by, updated_at)| FindingStatusRow {
                asset_id,
                cve_id,
                status,
                note,
                updated_by,
                updated_at,
            },
        )
        .collect())
}

/// Create or replace one triage decision.
pub async fn set_finding_status(
    pool: &PgPool,
    tenant_id: Uuid,
    asset_id: Uuid,
    cve_id: &str,
    status: &str,
    note: &str,
    updated_by: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO finding_status (tenant_id, asset_id, cve_id, status, note, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, now())
         ON CONFLICT (tenant_id, asset_id, cve_id)
         DO UPDATE SET status = EXCLUDED.status,
                       note = EXCLUDED.note,
                       updated_by = EXCLUDED.updated_by,
                       updated_at = now()",
    )
    .bind(tenant_id)
    .bind(asset_id)
    .bind(cve_id)
    .bind(status)
    .bind(note)
    .bind(updated_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a triage decision (the finding reverts to open). Returns whether a
/// row existed.
pub async fn clear_finding_status(
    pool: &PgPool,
    tenant_id: Uuid,
    asset_id: Uuid,
    cve_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM finding_status WHERE tenant_id = $1 AND asset_id = $2 AND cve_id = $3",
    )
    .bind(tenant_id)
    .bind(asset_id)
    .bind(cve_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Create or replace one CVE's triage decision on many assets in a single
/// statement (one round-trip, atomic).
pub async fn set_finding_statuses_bulk(
    pool: &PgPool,
    tenant_id: Uuid,
    asset_ids: &[Uuid],
    cve_id: &str,
    status: &str,
    note: &str,
    updated_by: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO finding_status (tenant_id, asset_id, cve_id, status, note, updated_by, updated_at)
         SELECT $1, unnest($2::uuid[]), $3, $4, $5, $6, now()
         ON CONFLICT (tenant_id, asset_id, cve_id)
         DO UPDATE SET status = EXCLUDED.status,
                       note = EXCLUDED.note,
                       updated_by = EXCLUDED.updated_by,
                       updated_at = EXCLUDED.updated_at",
    )
    .bind(tenant_id)
    .bind(asset_ids)
    .bind(cve_id)
    .bind(status)
    .bind(note)
    .bind(updated_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove one CVE's triage decision from many assets (they revert to open).
pub async fn clear_finding_statuses_bulk(
    pool: &PgPool,
    tenant_id: Uuid,
    asset_ids: &[Uuid],
    cve_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM finding_status
         WHERE tenant_id = $1 AND cve_id = $2 AND asset_id = ANY($3)",
    )
    .bind(tenant_id)
    .bind(cve_id)
    .bind(asset_ids)
    .execute(pool)
    .await?;
    Ok(())
}

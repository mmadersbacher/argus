//! Postgres store (sqlx): tenants, users, API keys, audit log, and the
//! tenant-scoped asset inventory.
//!
//! Schema is owned by the embedded sqlx migrations (`migrations/`). Every
//! asset query takes a `tenant_id` — there is deliberately no unscoped
//! variant, so cross-tenant leaks cannot be written by accident.

use argus_core::tenant::Role;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::seed::ScoredAsset;

/// Default connection string (overridable via the `DATABASE_URL` env var).
pub const DEFAULT_DATABASE_URL: &str = "postgresql://argus:argus@127.0.0.1:5432/argus";

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

/// Load one tenant's full inventory, highest risk first.
pub async fn load_all(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<ScoredAsset>, sqlx::Error> {
    let rows: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT body FROM assets WHERE tenant_id = $1 ORDER BY risk DESC")
            .bind(tenant_id)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(body,)| serde_json::from_value(body).ok())
        .collect())
}

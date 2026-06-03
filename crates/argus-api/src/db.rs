//! Postgres-backed inventory store (sqlx).
//!
//! Each scored asset is persisted as a JSONB document keyed by its correlation
//! key, with the numeric risk mirrored to a column for ordering. Simple,
//! queryable, and a clean fit for the document-shaped `ScoredAsset`.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::seed::ScoredAsset;

/// Default connection string (overridable via the `DATABASE_URL` env var).
pub const DEFAULT_DATABASE_URL: &str = "postgresql://argus:argus@127.0.0.1:5432/argus";

/// Connect, build the pool, and ensure the schema exists.
pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS assets (
            dedup_key  TEXT PRIMARY KEY,
            body       JSONB NOT NULL,
            risk       REAL NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )",
    )
    .execute(&pool)
    .await?;
    Ok(pool)
}

/// Number of assets currently in the inventory.
pub async fn count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM assets")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Insert or update an asset by its correlation key (dedup on repeated scans).
pub async fn upsert(pool: &PgPool, asset: &ScoredAsset) -> Result<(), sqlx::Error> {
    let body = serde_json::to_value(asset).expect("ScoredAsset serializes");
    sqlx::query(
        "INSERT INTO assets (dedup_key, body, risk, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (dedup_key)
         DO UPDATE SET body = EXCLUDED.body, risk = EXCLUDED.risk, updated_at = now()",
    )
    .bind(asset.asset.dedup_key())
    .bind(body)
    .bind(asset.risk.value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Load the full inventory, highest risk first.
pub async fn load_all(pool: &PgPool) -> Result<Vec<ScoredAsset>, sqlx::Error> {
    let rows: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT body FROM assets ORDER BY risk DESC")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(body,)| serde_json::from_value(body).ok())
        .collect())
}

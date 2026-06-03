//! Argus HTTP API server.
//!
//! Postgres-backed asset inventory (sqlx). Serves it to the console and exposes
//! `POST /api/scan` which runs discovery (nmap when available, else the built-in
//! connect scanner) and upserts the results into the inventory.
#![allow(clippy::unused_async, clippy::needless_pass_by_value)] // axum handler ergonomics

use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

mod db;
mod seed;

use seed::{scored_from_discovered, seed_assets, ScoredAsset, Summary};

/// Shared application state: the Postgres connection pool.
#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| db::DEFAULT_DATABASE_URL.to_owned());
    let pool = db::connect(&database_url)
        .await
        .expect("connect to Postgres (set DATABASE_URL or run the local argus DB)");

    // Seed the inventory only when the database is empty (first run).
    if db::count(&pool).await.expect("count assets") == 0 {
        tracing::info!("empty inventory — seeding demo assets");
        for asset in seed_assets() {
            db::upsert(&pool, &asset).await.expect("seed upsert");
        }
    }
    tracing::info!(
        assets = db::count(&pool).await.unwrap_or(0),
        "inventory ready"
    );

    let app = router(AppState { pool });
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8088));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind argus-api listener");
    tracing::info!("argus-api listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .expect("argus-api server error");
}

/// Build the application router. Kept separate from `main` for testability.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/assets", get(list_assets))
        .route("/api/assets/{id}", get(get_asset))
        .route("/api/summary", get(summary))
        .route("/api/scan", post(run_scan))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn db_error(err: sqlx::Error) -> (StatusCode, String) {
    tracing::error!(error = %err, "database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("database error: {err}"),
    )
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let assets = db::count(&state.pool).await.unwrap_or(0);
    Json(serde_json::json!({
        "status": "ok",
        "service": "argus-api",
        "version": env!("CARGO_PKG_VERSION"),
        "assets": assets,
    }))
}

async fn list_assets(
    State(state): State<AppState>,
) -> Result<Json<Vec<ScoredAsset>>, (StatusCode, String)> {
    db::load_all(&state.pool).await.map(Json).map_err(db_error)
}

async fn get_asset(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScoredAsset>, (StatusCode, String)> {
    let assets = db::load_all(&state.pool).await.map_err(db_error)?;
    assets
        .into_iter()
        .find(|a| a.asset.id.to_string() == id)
        .map(Json)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "asset not found".to_owned()))
}

async fn summary(State(state): State<AppState>) -> Result<Json<Summary>, (StatusCode, String)> {
    let assets = db::load_all(&state.pool).await.map_err(db_error)?;
    Ok(Json(Summary::from_assets(&assets)))
}

#[derive(Deserialize)]
struct ScanRequest {
    target: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    target: String,
    engine: &'static str,
    hosts_scanned: usize,
    live: usize,
    duration_ms: u64,
}

/// Run a discovery scan and upsert the results into the Postgres inventory.
///
/// Body: `{ "target": "<ip|cidr>" }` (defaults to `127.0.0.1`). Uses nmap when
/// installed, else the connect scanner. Discovered hosts are deduplicated by
/// correlation key, so repeated scans update rather than duplicate.
async fn run_scan(
    State(state): State<AppState>,
    body: Option<Json<ScanRequest>>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let target = body
        .and_then(|b| b.0.target)
        .unwrap_or_else(|| "127.0.0.1".to_owned());

    let ips =
        argus_discovery::expand(&target).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let started = Instant::now();
    let (engine, hosts) = if argus_discovery::nmap::available().await {
        match argus_discovery::nmap::scan(
            &target,
            argus_discovery::fingerprint::PORTS,
            Duration::from_secs(120),
        )
        .await
        {
            Ok(found) => ("nmap", found),
            Err(err) => {
                tracing::warn!(error = %err, "nmap failed; falling back to connect scan");
                let report = argus_discovery::scan(
                    &ips,
                    &argus_discovery::ScanOptions {
                        sample: true,
                        ..Default::default()
                    },
                )
                .await;
                ("connect", report.live)
            }
        }
    } else {
        let report = argus_discovery::scan(
            &ips,
            &argus_discovery::ScanOptions {
                sample: true,
                ..Default::default()
            },
        )
        .await;
        ("connect", report.live)
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let scored: Vec<ScoredAsset> = hosts.into_iter().map(scored_from_discovered).collect();
    let live = scored.len();
    for asset in &scored {
        db::upsert(&state.pool, asset).await.map_err(db_error)?;
    }

    tracing::info!(target = %target, engine, hosts = ips.len(), live, "scan complete");
    Ok(Json(ScanResponse {
        target,
        engine,
        hosts_scanned: ips.len(),
        live,
        duration_ms,
    }))
}

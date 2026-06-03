//! Argus HTTP API server.
//!
//! Holds the asset inventory in shared state, serves it to the console, and
//! exposes `POST /api/scan` which runs `argus-discovery` against a target and
//! merges the result into the inventory.
#![allow(clippy::unused_async, clippy::needless_pass_by_value)] // axum handler ergonomics

use std::sync::{Arc, RwLock};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

mod seed;

use seed::{scored_from_discovered, seed_assets, ScoredAsset, Summary};

/// Shared application state: the live asset inventory.
#[derive(Clone)]
struct AppState {
    assets: Arc<RwLock<Vec<ScoredAsset>>>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let state = AppState {
        assets: Arc::new(RwLock::new(seed_assets())),
    };
    let app = router(state);

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

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "argus-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_assets(State(state): State<AppState>) -> Json<Vec<ScoredAsset>> {
    let assets = state.assets.read().expect("assets lock poisoned").clone();
    Json(assets)
}

async fn get_asset(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScoredAsset>, StatusCode> {
    let assets = state.assets.read().expect("assets lock poisoned").clone();
    assets
        .into_iter()
        .find(|a| a.asset.id.to_string() == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn summary(State(state): State<AppState>) -> Json<Summary> {
    let assets = state.assets.read().expect("assets lock poisoned").clone();
    Json(Summary::from_assets(&assets))
}

#[derive(Deserialize)]
struct ScanRequest {
    target: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    target: String,
    hosts_scanned: usize,
    live: usize,
    duration_ms: u64,
}

/// Run a light discovery scan and merge the result into the inventory.
///
/// Body: `{ "target": "<ip|cidr>" }` (defaults to `127.0.0.1`). Discovered
/// hosts are deduplicated against the existing inventory by their correlation
/// key, so repeated scans update rather than duplicate.
async fn run_scan(
    State(state): State<AppState>,
    body: Option<Json<ScanRequest>>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let target = body
        .and_then(|b| b.0.target)
        .unwrap_or_else(|| "127.0.0.1".to_owned());

    let hosts =
        argus_discovery::expand(&target).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let report = argus_discovery::scan(&hosts, &argus_discovery::ScanOptions::default()).await;

    let scored: Vec<ScoredAsset> = report
        .live
        .into_iter()
        .map(scored_from_discovered)
        .collect();
    let live = scored.len();

    {
        let mut inventory = state.assets.write().expect("assets lock poisoned");
        for asset in scored {
            let key = asset.asset.dedup_key();
            inventory.retain(|existing| existing.asset.dedup_key() != key);
            inventory.push(asset);
        }
    }

    tracing::info!(target = %target, hosts = report.hosts_scanned, live, "scan complete");
    Ok(Json(ScanResponse {
        target,
        hosts_scanned: report.hosts_scanned,
        live,
        duration_ms: report.duration_ms,
    }))
}

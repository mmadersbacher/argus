//! Argus HTTP API server.
//!
//! Skeleton stage: serves seed data so the web console has something real to
//! render before the Postgres-backed inventory lands in P1.
#![allow(clippy::unused_async, clippy::needless_pass_by_value)] // axum handler ergonomics

use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

mod seed;

use seed::{seed_assets, ScoredAsset, Summary};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let app = router();
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
fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/assets", get(list_assets))
        .route("/api/assets/{id}", get(get_asset))
        .route("/api/summary", get(summary))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "argus-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_assets() -> Json<Vec<ScoredAsset>> {
    Json(seed_assets())
}

async fn get_asset(Path(id): Path<String>) -> Result<Json<ScoredAsset>, StatusCode> {
    seed_assets()
        .into_iter()
        .find(|a| a.asset.id.to_string() == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn summary() -> Json<Summary> {
    Json(Summary::from_assets(&seed_assets()))
}

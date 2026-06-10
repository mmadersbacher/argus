//! Argus HTTP API server.
//!
//! Postgres-backed, multi-tenant asset inventory (sqlx) behind JWT/API-key
//! authentication with role-based access control. Serves the console and
//! exposes `POST /api/scan`, which runs discovery (nmap when available, else
//! the built-in connect scanner) and upserts results into the caller's
//! tenant inventory.
#![allow(clippy::unused_async, clippy::needless_pass_by_value)] // axum handler ergonomics

use std::sync::Arc;
use std::time::{Duration, Instant};

use argus_core::tenant::Role;
use axum::extract::{Path, State};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod account;
mod auth;
mod db;
mod seed;

use auth::{AuthContext, AuthKeys, LoginLimiter};
use seed::{scored_from_discovered, seed_assets, ScoredAsset, Summary};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Postgres connection pool.
    pub pool: PgPool,
    /// JWT signing/verification keys.
    pub keys: AuthKeys,
    /// Login brute-force limiter.
    pub limiter: Arc<LoginLimiter>,
    /// Whether `POST /api/auth/register` is open (`ARGUS_SIGNUP_ENABLED`).
    pub signup_enabled: bool,
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

    bootstrap(&pool).await;

    let state = AppState {
        pool,
        keys: AuthKeys::from_secret(&auth::load_or_generate_secret()),
        limiter: Arc::new(LoginLimiter::default()),
        signup_enabled: env_flag("ARGUS_SIGNUP_ENABLED", true),
    };

    let app = router(state);
    let bind = std::env::var("ARGUS_BIND").unwrap_or_else(|_| "127.0.0.1:8088".to_owned());
    let listener = tokio::net::TcpListener::bind(bind.as_str())
        .await
        .expect("bind argus-api listener");
    tracing::info!("argus-api listening on http://{bind}");
    axum::serve(listener, app)
        .await
        .expect("argus-api server error");
}

/// Read a boolean env flag with a default ("false"/"0"/"no" disable it).
fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name).map_or(default, |v| {
        !matches!(v.trim().to_lowercase().as_str(), "false" | "0" | "no")
    })
}

/// First-run bootstrap: create the default tenant + admin user (and demo
/// assets unless `ARGUS_SEED_DEMO=false`) when no tenant exists yet.
async fn bootstrap(pool: &PgPool) {
    if db::tenant_count(pool).await.expect("count tenants") > 0 {
        return;
    }
    let tenant_id = Uuid::new_v4();
    db::create_tenant(pool, tenant_id, "Default", "default")
        .await
        .expect("create bootstrap tenant");

    let email = std::env::var("ARGUS_ADMIN_EMAIL").map_or_else(
        |_| "admin@argus.local".to_owned(),
        |e| e.trim().to_lowercase(),
    );
    let (password, generated) = std::env::var("ARGUS_ADMIN_PASSWORD").map_or_else(
        |_| {
            let pw: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();
            (pw, true)
        },
        |pw| (pw, false),
    );
    let user = db::UserRow {
        id: Uuid::new_v4(),
        tenant_id,
        email: email.clone(),
        password_hash: auth::hash_password(&password).expect("hash bootstrap password"),
        role: Role::Admin,
    };
    db::create_user(pool, &user)
        .await
        .expect("create bootstrap admin");
    if generated {
        // Printed exactly once, on first boot. There is no other way to
        // recover this credential — log loudly.
        tracing::warn!("bootstrap admin created: {email}");
        tracing::warn!("bootstrap admin password (change it after login): {password}");
    } else {
        tracing::info!("bootstrap admin created: {email} (password from ARGUS_ADMIN_PASSWORD)");
    }

    if env_flag("ARGUS_SEED_DEMO", true) {
        tracing::info!("seeding demo assets into the default tenant");
        for asset in seed_assets() {
            db::upsert(pool, tenant_id, &asset)
                .await
                .expect("seed upsert");
        }
    }
}

/// CORS restricted to the console origin(s) from `ARGUS_CORS_ORIGIN`
/// (comma-separated; defaults to the local dev console).
fn cors_layer() -> CorsLayer {
    let origins = std::env::var("ARGUS_CORS_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000,http://127.0.0.1:3000".to_owned());
    let list: Vec<HeaderValue> = origins
        .split(',')
        .filter_map(|origin| origin.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(list))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static(auth::API_KEY_HEADER),
        ])
}

/// Build the application router. Kept separate from `main` for testability.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/auth/register", post(account::register))
        .route("/api/auth/login", post(account::login))
        .route("/api/auth/me", get(account::me))
        .route(
            "/api/users",
            get(account::list_users).post(account::create_user),
        )
        .route(
            "/api/api-keys",
            get(account::list_api_keys).post(account::create_api_key),
        )
        .route("/api/api-keys/{id}", delete(account::delete_api_key))
        .route("/api/assets", get(list_assets))
        .route("/api/assets/{id}", get(get_asset))
        .route("/api/summary", get(summary))
        .route("/api/scan", post(run_scan))
        .route("/api/import/nmap", post(import_nmap))
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Map a database error to an opaque 500 (details only in the server log).
pub(crate) fn db_error(err: sqlx::Error) -> (StatusCode, String) {
    tracing::error!(error = %err, "database error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal database error".to_owned(),
    )
}

/// Unauthenticated liveness probe. Deliberately leaks no inventory data.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "argus-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_assets(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<ScoredAsset>>, (StatusCode, String)> {
    db::load_all(&state.pool, auth.tenant_id)
        .await
        .map(Json)
        .map_err(db_error)
}

async fn get_asset(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScoredAsset>, (StatusCode, String)> {
    let assets = db::load_all(&state.pool, auth.tenant_id)
        .await
        .map_err(db_error)?;
    assets
        .into_iter()
        .find(|a| a.asset.id.to_string() == id)
        .map(Json)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "asset not found".to_owned()))
}

async fn summary(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Summary>, (StatusCode, String)> {
    let assets = db::load_all(&state.pool, auth.tenant_id)
        .await
        .map_err(db_error)?;
    Ok(Json(Summary::from_assets(&assets)))
}

#[derive(Deserialize)]
struct ScanRequest {
    target: Option<String>,
    /// Privileged deep scan: masscan high-speed sweep + nmap SYN/OS detection.
    /// Needs root; falls back to the standard scan when unavailable.
    deep: Option<bool>,
}

#[derive(Serialize)]
struct ScanResponse {
    target: String,
    engine: &'static str,
    hosts_scanned: usize,
    live: usize,
    duration_ms: u64,
}

/// Run a discovery scan and upsert the results into the caller's inventory.
///
/// Requires the `analyst` role. Body: `{ "target": "<ip|cidr>" }` (defaults
/// to `127.0.0.1`). Uses nmap when installed, else the connect scanner.
/// Discovered hosts are deduplicated by correlation key, so repeated scans
/// update rather than duplicate.
async fn run_scan(
    auth: AuthContext,
    State(state): State<AppState>,
    body: Option<Json<ScanRequest>>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    auth.require(Role::Analyst)?;
    let req = body.map_or(
        ScanRequest {
            target: None,
            deep: None,
        },
        |b| b.0,
    );
    let target = req.target.unwrap_or_else(|| "127.0.0.1".to_owned());
    let deep = req.deep.unwrap_or(false);

    let ips =
        argus_discovery::expand(&target).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let started = Instant::now();

    // Deep scan first when requested: masscan high-speed sweep + nmap SYN/OS
    // detail (both need root). Best-effort — an empty result (unprivileged, or
    // nothing live) falls through to the standard nmap/connect path below.
    let deep_hosts = if deep {
        argus_discovery::deep_scan(
            &target,
            argus_discovery::fingerprint::PORTS,
            argus_discovery::masscan::DEFAULT_RATE,
            Duration::from_secs(120),
        )
        .await
    } else {
        Vec::new()
    };

    let (engine, hosts) = if !deep_hosts.is_empty() {
        ("masscan+nmap-os", deep_hosts)
    } else if argus_discovery::nmap::available().await {
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

    let live = ingest(&state.pool, auth.tenant_id, hosts).await?;
    db::audit(
        &state.pool,
        auth.tenant_id,
        auth.user_id,
        "scan.run",
        serde_json::json!({ "target": target, "engine": engine, "live": live }),
    )
    .await;

    tracing::info!(target = %target, engine, hosts = ips.len(), live, "scan complete");
    Ok(Json(ScanResponse {
        target,
        engine,
        hosts_scanned: ips.len(),
        live,
        duration_ms,
    }))
}

/// Persist discovered hosts into one tenant's inventory: classify
/// (argus-intel), enrich with live CVE intelligence (NVD/KEV/EPSS),
/// recompute risk, and upsert. Shared by live scans and the nmap-XML import.
async fn ingest(
    pool: &PgPool,
    tenant_id: Uuid,
    hosts: Vec<argus_discovery::DiscoveredHost>,
) -> Result<usize, (StatusCode, String)> {
    let mut scored: Vec<ScoredAsset> = hosts.into_iter().map(scored_from_discovered).collect();
    let n = scored.len();
    for asset in &mut scored {
        // Refine classification from vendor + ports + services (argus-intel).
        let cls = argus_intel::classify(&argus_intel::Features {
            vendor: asset.asset.fingerprint.vendor.clone(),
            open_ports: asset.services.iter().map(|s| s.port).collect(),
            services: asset
                .services
                .iter()
                .filter_map(|s| s.product.clone())
                .collect(),
            os: asset.asset.fingerprint.os.clone(),
        });
        asset.asset.asset_type = cls.asset_type;
        asset.asset.fingerprint.device_type = Some(cls.device_type);
        asset.asset.fingerprint.confidence = cls.confidence;

        // Live enrichment: NVD search for the asset's products + authoritative
        // CISA-KEV + current EPSS, then recompute risk. Best-effort (falls back
        // to the catalog-derived vulns/risk if the feeds are unavailable).
        let products: Vec<String> = asset
            .services
            .iter()
            .filter_map(|s| s.product.clone())
            .collect();
        let enriched =
            argus_vuln::nvd::enrich(std::mem::take(&mut asset.vulnerabilities), &products).await;
        asset.risk = argus_core::RiskScore::compute(&argus_vuln::risk_inputs(
            &enriched,
            asset.asset.exposure,
            asset.asset.criticality,
        ));
        asset.vulnerabilities = enriched;
        db::upsert(pool, tenant_id, asset).await.map_err(db_error)?;
    }
    Ok(n)
}

#[derive(Serialize)]
struct ImportResponse {
    source: &'static str,
    imported: usize,
}

/// Import an external `nmap -oX` XML export (raw request body) into the
/// caller's inventory. Requires the `analyst` role.
///
/// Parsed into hosts and run through the same classify → enrich → score →
/// upsert pipeline as a live scan, then deduplicated by correlation key.
async fn import_nmap(
    auth: AuthContext,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<ImportResponse>, (StatusCode, String)> {
    auth.require(Role::Analyst)?;
    if body.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "empty body — POST the output of `nmap -oX -`".to_owned(),
        ));
    }
    let hosts = argus_discovery::nmap::parse(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("nmap XML: {e}")))?;
    let imported = ingest(&state.pool, auth.tenant_id, hosts).await?;
    db::audit(
        &state.pool,
        auth.tenant_id,
        auth.user_id,
        "import.nmap",
        serde_json::json!({ "imported": imported }),
    )
    .await;
    tracing::info!(imported, "nmap import complete");
    Ok(Json(ImportResponse {
        source: "nmap-xml",
        imported,
    }))
}

//! Argus HTTP API server.
//!
//! Postgres-backed, multi-tenant asset inventory (sqlx) behind JWT/API-key
//! authentication with role-based access control. Serves the console and
//! exposes `POST /api/scan`, which runs discovery (nmap when available, else
//! the built-in connect scanner) and upserts results into the caller's
//! tenant inventory.
#![allow(clippy::unused_async, clippy::needless_pass_by_value)] // axum handler ergonomics

use std::net::SocketAddr;
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
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod account;
mod auth;
mod db;
mod monitor;
mod seed;
mod store;
mod vulns;

use auth::{AuthContext, AuthKeys, LoginLimiter};
use seed::{scored_from_discovered, seed_assets, ScoredAsset, Summary};
use store::{IngestLocks, Store, StoreError};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Backing store (Postgres or in-memory).
    pub store: Store,
    /// JWT signing/verification keys.
    pub keys: AuthKeys,
    /// Login brute-force limiter.
    pub limiter: Arc<LoginLimiter>,
    /// Whether `POST /api/auth/register` is open (`ARGUS_SIGNUP_ENABLED`).
    pub signup_enabled: bool,
    /// Per-tenant ingest serialization (manual scans vs. scheduled runs).
    pub ingest_locks: IngestLocks,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let store = select_store().await;
    tracing::info!(backend = store.label(), "storage ready");
    bootstrap(&store).await;

    let ingest_locks = IngestLocks::default();
    let state = AppState {
        store,
        keys: AuthKeys::from_secret(&auth::load_or_generate_secret()),
        limiter: Arc::new(LoginLimiter::default()),
        signup_enabled: env_flag("ARGUS_SIGNUP_ENABLED", true),
        ingest_locks: ingest_locks.clone(),
    };

    spawn_scheduler(state.store.clone(), ingest_locks);

    let app = router(state);
    let bind = std::env::var("ARGUS_BIND").unwrap_or_else(|_| "127.0.0.1:8088".to_owned());
    let listener = tokio::net::TcpListener::bind(bind.as_str())
        .await
        .expect("bind argus-api listener");
    tracing::info!("argus-api listening on http://{bind}");
    // `into_make_service_with_connect_info` exposes the client socket address
    // to handlers (ConnectInfo<SocketAddr>) — used by the login rate limiter.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("argus-api server error");
}

/// Read a boolean env flag. An unset OR empty/whitespace value falls back to
/// `default` (fail-safe: e.g. `ARGUS_SIGNUP_ENABLED=` does not silently enable
/// signup); otherwise "false"/"0"/"no" disable, anything else enables.
fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => {
            !matches!(v.trim().to_lowercase().as_str(), "false" | "0" | "no")
        }
        _ => default,
    }
}

/// Choose the storage backend.
///
/// `ARGUS_STORE=memory` forces the in-memory store. Otherwise `DATABASE_URL`
/// selects Postgres (the deployment default); when it is unset we fall back to
/// the in-memory store so the API runs with zero dependencies for local dev.
async fn select_store() -> Store {
    let force_memory =
        std::env::var("ARGUS_STORE").is_ok_and(|v| v.trim().eq_ignore_ascii_case("memory"));
    if force_memory {
        return Store::memory();
    }
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = db::connect(&url).await.expect(
            "connect to Postgres (set DATABASE_URL, or unset it to use the in-memory store)",
        );
        Store::Postgres(pool)
    } else {
        tracing::warn!(
            "DATABASE_URL not set — using the in-memory store (data is lost on restart; \
             local dev only). Set DATABASE_URL for persistence."
        );
        Store::memory()
    }
}

/// First-run bootstrap: create the default tenant + admin user (and demo
/// assets unless `ARGUS_SEED_DEMO=false`) when no tenant exists yet.
async fn bootstrap(store: &Store) {
    if store.tenant_count().await.expect("count tenants") > 0 {
        return;
    }
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
    let tenant_id = Uuid::new_v4();
    let user = db::UserRow {
        id: Uuid::new_v4(),
        tenant_id,
        email: email.clone(),
        password_hash: auth::hash_password(&password).expect("hash bootstrap password"),
        role: Role::Admin,
    };
    store
        .register_tenant(tenant_id, "Default", "default", &user)
        .await
        .expect("create bootstrap tenant + admin");
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
            store.upsert(tenant_id, &asset).await.expect("seed upsert");
        }
    }
}

/// CORS restricted to the console origin(s) from `ARGUS_CORS_ORIGIN`
/// (comma-separated; defaults to the local dev console).
fn cors_layer() -> CorsLayer {
    let origins = std::env::var("ARGUS_CORS_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000,http://127.0.0.1:3000".to_owned());
    let mut list: Vec<HeaderValue> = Vec::new();
    for origin in origins.split(',').map(str::trim).filter(|o| !o.is_empty()) {
        if let Ok(value) = origin.parse() {
            list.push(value);
        } else {
            tracing::warn!(origin, "ignoring invalid ARGUS_CORS_ORIGIN entry");
        }
    }
    if list.is_empty() {
        tracing::warn!(
            "ARGUS_CORS_ORIGIN produced an empty allow-list — the browser console \
             will be blocked by CORS. Check the value."
        );
    }
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
        .route("/api/vulns", get(vulns::list_vulns))
        .route("/api/events", get(monitor::list_events))
        .route(
            "/api/monitor",
            get(monitor::get_monitor).post(monitor::set_monitor),
        )
        .route("/api/scan", post(run_scan))
        .route("/api/import/nmap", post(import_nmap))
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Map a store error to an HTTP response: conflicts surface as 409, everything
/// else as an opaque 500 (details only in the server log).
pub(crate) fn store_error(err: StoreError) -> (StatusCode, String) {
    match err {
        StoreError::Conflict(msg) => (StatusCode::CONFLICT, msg.to_owned()),
        StoreError::Backend(detail) => {
            tracing::error!(error = %detail, "store error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal database error".to_owned(),
            )
        }
    }
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
    state
        .store
        .load_all(auth.tenant_id)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn get_asset(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ScoredAsset>, (StatusCode, String)> {
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
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
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
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
    /// Number of change events this scan produced (see `GET /api/events`).
    changes: usize,
}

/// Outcome of one discovery run: which engine ran and what it found.
struct Discovery {
    /// Engine label (`masscan+nmap-os`, `nmap`, or `connect`).
    engine: &'static str,
    /// Live hosts found.
    hosts: Vec<argus_discovery::DiscoveredHost>,
    /// Number of candidate addresses the target spec expanded to.
    candidates: usize,
}

/// Expand `target` and run discovery with the best available engine: the
/// privileged deep path (masscan sweep + nmap SYN/OS, needs root) when
/// requested, else nmap when installed, else the built-in connect scanner.
/// Shared by `POST /api/scan` and the monitor scheduler.
async fn discover(target: &str, deep: bool) -> Result<Discovery, argus_discovery::TargetError> {
    let ips = argus_discovery::expand(target)?;

    // Deep scan first when requested. Best-effort — an empty result
    // (unprivileged, or nothing live) falls through to the standard
    // nmap/connect path below.
    let deep_hosts = if deep {
        argus_discovery::deep_scan(
            target,
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
            target,
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
    Ok(Discovery {
        engine,
        hosts,
        candidates: ips.len(),
    })
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

    let started = Instant::now();
    let discovery = discover(&target, deep)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let Discovery {
        engine,
        hosts,
        candidates,
    } = discovery;
    let (live, changes) = ingest(&state.store, &state.ingest_locks, auth.tenant_id, hosts).await?;
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "scan.run",
            serde_json::json!({ "target": target, "engine": engine, "live": live }),
        )
        .await;

    tracing::info!(target = %target, engine, hosts = candidates, live, changes, "scan complete");
    Ok(Json(ScanResponse {
        target,
        engine,
        hosts_scanned: candidates,
        live,
        duration_ms,
        changes,
    }))
}

/// Decide the vulnerabilities and risk to persist for one asset, given the
/// previous stored asset and a freshly attempted live enrichment.
///
/// The diff in `monitor::diff` runs enriched-vs-enriched. If we let an asset's
/// vuln set oscillate between the full enriched set and a partial/catalog-only
/// set whenever a feed times out, the diff would report the same CVEs removed
/// then re-added on every flap (false `vulns.changed` / `risk.changed` spam).
/// So enrichment is made NON-REGRESSIVE:
///
/// - If the feeds were fully reachable (`enrichment.live`) OR there is no
///   previous asset, use the fresh enriched vulns/risk (the current behaviour).
/// - Otherwise (feeds not fully reachable AND a previous asset exists), keep the
///   previous asset's vulns/risk verbatim — do NOT regress to a partial set.
///
/// Pure and network-free (the enrichment is performed by the caller), so the
/// decision is unit-testable without touching the live feeds.
fn choose_vulns_risk(
    prev: Option<&ScoredAsset>,
    enrichment: argus_vuln::nvd::Enrichment,
    exposure: argus_core::Exposure,
    criticality: argus_core::Criticality,
) -> (Vec<argus_core::Vulnerability>, argus_core::RiskScore) {
    match prev {
        Some(prev) if !enrichment.live => {
            // Non-regressive: a partial enrichment must not become the new diff
            // baseline. Reuse the previous enriched vulns/risk so the next diff
            // is stable across the feed outage.
            (prev.vulnerabilities.clone(), prev.risk)
        }
        _ => {
            let risk = argus_core::RiskScore::compute(&argus_vuln::risk_inputs(
                &enrichment.vulns,
                exposure,
                criticality,
            ));
            (enrichment.vulns, risk)
        }
    }
}

/// Persist discovered hosts into one tenant's inventory: classify
/// (argus-intel), enrich with live CVE intelligence (NVD/KEV/EPSS), recompute
/// risk, diff against the previously stored asset (change events), and upsert.
/// Shared by live scans, scheduled monitor runs, and the nmap-XML import.
///
/// The whole body holds the per-tenant ingest lock so a manual scan and a
/// scheduled run for the same tenant cannot interleave and advance the diff
/// baseline against each other (duplicating events). Asset upsert + event
/// recording commit atomically per asset via `commit_asset`.
///
/// Returns `(live_hosts, change_events)`.
async fn ingest(
    store: &Store,
    ingest_locks: &IngestLocks,
    tenant_id: Uuid,
    hosts: Vec<argus_discovery::DiscoveredHost>,
) -> Result<(usize, usize), (StatusCode, String)> {
    let _guard = ingest_locks.lock(tenant_id).await;
    let mut scored: Vec<ScoredAsset> = hosts.into_iter().map(scored_from_discovered).collect();
    let n = scored.len();
    let mut changes = 0;
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
        // CISA-KEV + current EPSS, with a reachability signal so change
        // detection runs on stable, non-regressive data (see choose_vulns_risk).
        let products: Vec<String> = asset
            .services
            .iter()
            .filter_map(|s| s.product.clone())
            .collect();
        let enrichment =
            argus_vuln::nvd::enrich_checked(std::mem::take(&mut asset.vulnerabilities), &products)
                .await;

        // Change detection against the previously stored asset (by correlation
        // key): carry forward identity (id + first_seen), stamp last_seen, then
        // pick the vulns/risk (non-regressive on partial enrichment).
        let dedup_key = asset.asset.dedup_key();
        let previous = store
            .load_one(tenant_id, &dedup_key)
            .await
            .map_err(store_error)?;
        if let Some(prev) = &previous {
            monitor::carry_forward(prev, asset);
        }
        let (vulns, risk) = choose_vulns_risk(
            previous.as_ref(),
            enrichment,
            asset.asset.exposure,
            asset.asset.criticality,
        );
        asset.vulnerabilities = vulns;
        asset.risk = risk;

        let events = monitor::diff(previous.as_ref(), asset);
        let name = monitor::asset_name(asset);
        changes += events.len();
        let event_refs: Vec<(&str, &serde_json::Value)> =
            events.iter().map(|e| (e.kind, &e.detail)).collect();
        store
            .commit_asset(tenant_id, asset, &event_refs, &dedup_key, &name)
            .await
            .map_err(store_error)?;
    }
    Ok((n, changes))
}

/// Max number of scheduled scans that run concurrently across all tenants.
const SCHEDULER_CONCURRENCY: usize = 4;
/// Event retention window (days) applied by the periodic prune.
const EVENT_RETENTION_DAYS: i64 = 90;
/// Run the prune roughly once per hour: ticks are 30s, so every 120 ticks.
const PRUNE_EVERY_TICKS: u64 = 120;

/// Spawn the continuous-monitoring scheduler as a background task.
///
/// Ticks every 30s and atomically claims all due monitors (the claim stamps
/// `last_run_at` *before* the scan runs, so a slow scan cannot be picked up
/// again by the next tick). Each claimed monitor is spawned as its own task
/// (bounded by a `Semaphore` to `SCHEDULER_CONCURRENCY` permits), so a slow or
/// deep scan for one tenant cannot block every other tenant — and the tick loop
/// keeps ticking regardless. Per-monitor overlap is already prevented by the
/// atomic claim, so spawning concurrently is safe. Failures of one tenant's run
/// are logged and never kill the scheduler task.
///
/// Designed for a single API instance. Because claiming is one atomic
/// `UPDATE .. RETURNING` (or the equivalent under the memory mutex), multiple
/// replicas remain best-effort safe: each due monitor is claimed by at most
/// one replica per interval.
fn spawn_scheduler(store: Store, ingest_locks: IngestLocks) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(SCHEDULER_CONCURRENCY));
        let mut ticks: u64 = 0;
        loop {
            tick.tick().await;
            ticks = ticks.wrapping_add(1);

            // Bound unbounded event growth: prune roughly hourly, not per tick.
            if ticks % PRUNE_EVERY_TICKS == 0 {
                match store.prune_events(EVENT_RETENTION_DAYS).await {
                    Ok(pruned) => tracing::info!(pruned, "pruned old change events"),
                    Err(err) => tracing::error!(error = ?err, "event prune failed"),
                }
            }

            let due = match store.claim_due_monitors().await {
                Ok(due) => due,
                Err(err) => {
                    tracing::error!(error = ?err, "monitor claim failed");
                    continue;
                }
            };
            for claimed in due {
                let store = store.clone();
                let ingest_locks = ingest_locks.clone();
                let semaphore = Arc::clone(&semaphore);
                tokio::spawn(async move {
                    // Acquire a permit inside the task so the tick loop never
                    // blocks; the permit drops when the task ends.
                    let _permit = semaphore.acquire_owned().await;
                    run_scheduled_scan(&store, &ingest_locks, &claimed).await;
                });
            }
        }
    });
}

/// Execute one scheduled scan for one tenant. Errors are logged, not returned —
/// a failing tenant run must not affect the scheduler or other tenants.
async fn run_scheduled_scan(store: &Store, ingest_locks: &IngestLocks, claimed: &db::DueMonitor) {
    let result = async {
        let discovery = discover(&claimed.target, claimed.deep)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let (live, changes) =
            ingest(store, ingest_locks, claimed.tenant_id, discovery.hosts).await?;
        // Only emit an audit row when something actually changed — a stable
        // monitor must not write one audit row per (zero-change) run forever.
        if changes > 0 {
            store
                .audit(
                    claimed.tenant_id,
                    None,
                    "scan.scheduled",
                    serde_json::json!({
                        "target": claimed.target,
                        "engine": discovery.engine,
                        "live": live,
                        "changes": changes,
                    }),
                )
                .await;
        }
        tracing::info!(
            tenant = %claimed.tenant_id,
            target = %claimed.target,
            engine = discovery.engine,
            live,
            changes,
            "scheduled scan complete"
        );
        Ok::<(), (StatusCode, String)>(())
    }
    .await;
    if let Err((_, message)) = result {
        tracing::error!(
            tenant = %claimed.tenant_id,
            target = %claimed.target,
            error = %message,
            "scheduled scan failed"
        );
    }
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
    let (imported, _changes) =
        ingest(&state.store, &state.ingest_locks, auth.tenant_id, hosts).await?;
    state
        .store
        .audit(
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

#[cfg(test)]
mod tests {
    use argus_core::{
        Asset, AssetId, AssetType, Criticality, Cvss, Exposure, Fingerprint, Protocol, RiskBand,
        RiskScore, Service, Severity, Vulnerability,
    };
    use argus_vuln::nvd::Enrichment;
    use time::OffsetDateTime;

    use super::*;

    fn vuln(cve: &str, kev: bool, cvss: f32) -> Vulnerability {
        Vulnerability {
            cve_id: cve.to_owned(),
            cvss: Some(Cvss {
                base_score: cvss,
                vector: None,
            }),
            epss: None,
            kev,
            severity: Severity::from_cvss(cvss),
        }
    }

    fn asset_with(vulns: Vec<Vulnerability>, risk_value: f32) -> ScoredAsset {
        ScoredAsset {
            asset: Asset {
                id: AssetId::new(),
                asset_type: AssetType::It,
                criticality: Criticality::Medium,
                exposure: Exposure::Internal,
                fingerprint: Fingerprint::default(),
                interfaces: Vec::new(),
                first_seen: OffsetDateTime::UNIX_EPOCH,
                last_seen: OffsetDateTime::UNIX_EPOCH,
            },
            services: vec![Service {
                port: 443,
                protocol: Protocol::Tcp,
                product: Some("nginx".to_owned()),
                banner: None,
            }],
            vulnerabilities: vulns,
            risk: RiskScore {
                value: risk_value,
                band: RiskBand::from_value(risk_value),
            },
        }
    }

    #[test]
    fn live_enrichment_uses_fresh_vulns_and_risk() {
        let prev = asset_with(vec![vuln("CVE-2020-1", false, 5.0)], 30.0);
        let enrichment = Enrichment {
            vulns: vec![vuln("CVE-2024-9", true, 9.8)],
            live: true,
        };
        let (vulns, risk) = choose_vulns_risk(
            Some(&prev),
            enrichment,
            Exposure::InternetFacing,
            Criticality::High,
        );
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cve_id, "CVE-2024-9");
        // Recomputed from the fresh, KEV-floored, high-CVSS vuln.
        assert!(risk.value > prev.risk.value);
    }

    #[test]
    fn no_previous_asset_uses_fresh_even_if_not_live() {
        let enrichment = Enrichment {
            vulns: vec![vuln("CVE-2024-9", false, 7.5)],
            live: false,
        };
        let (vulns, _risk) =
            choose_vulns_risk(None, enrichment, Exposure::Internal, Criticality::Low);
        assert_eq!(vulns[0].cve_id, "CVE-2024-9");
    }

    #[test]
    fn partial_enrichment_with_previous_keeps_prev_and_emits_no_vuln_or_risk_change() {
        // Previous asset was enriched (full vuln set, computed risk).
        let mut prev = asset_with(vec![vuln("CVE-2024-9", true, 9.8)], 92.0);
        prev.asset.last_seen = OffsetDateTime::UNIX_EPOCH;

        // This run: a feed failed (live=false) and the partial set regressed to
        // catalog-only (here: empty). Without the non-regressive guard, the
        // diff would report CVE-2024-9 removed and the risk band flap.
        let enrichment = Enrichment {
            vulns: Vec::new(),
            live: false,
        };

        // Build the fresh asset exactly as ingest would: carry forward identity
        // then apply choose_vulns_risk.
        let mut fresh = asset_with(Vec::new(), 0.0);
        monitor::carry_forward(&prev, &mut fresh);
        let (vulns, risk) = choose_vulns_risk(
            Some(&prev),
            enrichment,
            fresh.asset.exposure,
            fresh.asset.criticality,
        );
        fresh.vulnerabilities = vulns;
        fresh.risk = risk;

        // The previous enriched vulns/risk are kept verbatim.
        assert_eq!(fresh.vulnerabilities.len(), 1);
        assert_eq!(fresh.vulnerabilities[0].cve_id, "CVE-2024-9");
        assert!((fresh.risk.value - prev.risk.value).abs() < f32::EPSILON);

        // And the enriched-vs-enriched diff emits no vuln/risk churn (services
        // are identical here too, so diff is empty).
        let events = monitor::diff(Some(&prev), &fresh);
        assert!(
            !events
                .iter()
                .any(|e| e.kind == "vulns.changed" || e.kind == "risk.changed"),
            "non-regressive enrichment must not emit vulns/risk churn on feed failure"
        );
    }
}

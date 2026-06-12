//! `POST /api/findings` (+ `/bulk`) — analyst triage of (asset, CVE) findings.
//!
//! IR workflow v1: a finding is `open` by default; analysts set
//! `acknowledged` / `resolved` / `false_positive` (with an optional note),
//! or `open` to clear the decision. The status is keyed by the stable asset
//! id + CVE id, so it survives re-scans, and it is triage metadata only —
//! the computed risk score is deliberately not altered (an accepted risk is
//! still a risk; the console shows both). The bulk route applies one
//! decision to many assets of a single CVE in one call.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::vulns::FindingState;
use crate::{store_error, AppState};

/// Longest accepted analyst note.
const MAX_NOTE: usize = 500;

/// Most assets accepted per bulk call — far above any real CVE blast radius,
/// just a backstop against absurd payloads.
const MAX_BULK: usize = 1000;

/// Valid triage statuses (besides `open`, which clears the row).
const STATUSES: &[&str] = &["acknowledged", "resolved", "false_positive"];

/// Validate the shared (cve, status, note) triple of both triage routes.
/// Returns the trimmed values.
fn validate<'r>(
    cve_id: &'r str,
    status: &'r str,
    note: Option<String>,
) -> Result<(&'r str, &'r str, String), (StatusCode, String)> {
    let cve_id = cve_id.trim();
    if cve_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "cve_id must not be empty".into()));
    }
    let note = note.unwrap_or_default().trim().to_owned();
    if note.chars().count() > MAX_NOTE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("note exceeds {MAX_NOTE} characters"),
        ));
    }
    let status = status.trim();
    if status != "open" && !STATUSES.contains(&status) {
        return Err((
            StatusCode::BAD_REQUEST,
            "status must be one of: open, acknowledged, resolved, false_positive".into(),
        ));
    }
    Ok((cve_id, status, note))
}

#[derive(Deserialize)]
pub struct SetFindingRequest {
    /// Asset carrying the finding.
    asset_id: Uuid,
    /// CVE identifier of the finding.
    cve_id: String,
    /// `open` (clears the decision), `acknowledged`, `resolved` or
    /// `false_positive`.
    status: String,
    /// Optional analyst note (max 500 chars; ignored for `open`).
    note: Option<String>,
}

/// Set or clear the triage status of one finding. Requires the `analyst`
/// role. Returns the new state, or `null` when the finding is back to open.
pub async fn set_finding(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<SetFindingRequest>,
) -> Result<Json<Option<FindingState>>, (StatusCode, String)> {
    auth.require(argus_core::tenant::Role::Analyst)?;

    let (cve_id, status, note) = validate(&req.cve_id, &req.status, req.note)?;

    // The finding must exist in the inventory: triage decisions attach to
    // observed (asset, CVE) pairs, never to arbitrary ids.
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
    let exists = assets.iter().any(|a| {
        a.asset.id.0 == req.asset_id && a.vulnerabilities.iter().any(|v| v.cve_id == cve_id)
    });
    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            "no such finding (asset + CVE) in the inventory".into(),
        ));
    }

    let updated_by = auth.email.clone().unwrap_or_else(|| "api-key".to_owned());
    let result = if status == "open" {
        state
            .store
            .clear_finding_status(auth.tenant_id, req.asset_id, cve_id)
            .await
            .map_err(store_error)?;
        None
    } else {
        state
            .store
            .set_finding_status(
                auth.tenant_id,
                req.asset_id,
                cve_id,
                status,
                &note,
                &updated_by,
            )
            .await
            .map_err(store_error)?;
        Some(FindingState {
            status: status.to_owned(),
            note,
            updated_by: updated_by.clone(),
            updated_at: time::OffsetDateTime::now_utc(),
        })
    };

    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "finding.status",
            serde_json::json!({
                "asset_id": req.asset_id,
                "cve_id": cve_id,
                "status": status,
            }),
        )
        .await;
    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct SetFindingsBulkRequest {
    /// CVE whose findings are being triaged.
    cve_id: String,
    /// Assets to apply the decision to (deduplicated server-side).
    asset_ids: Vec<Uuid>,
    /// `open` (clears the decisions), `acknowledged`, `resolved` or
    /// `false_positive`.
    status: String,
    /// Optional shared analyst note (max 500 chars; ignored for `open`).
    note: Option<String>,
}

/// Result of a bulk triage call.
#[derive(Debug, Serialize)]
pub struct BulkOutcome {
    /// Findings the decision was applied to.
    pub updated: usize,
    /// Requested assets that do not carry the CVE (e.g. gone since the
    /// console last polled) — nothing was written for these.
    pub skipped: Vec<Uuid>,
}

/// Set or clear the triage status of one CVE across many assets. Requires
/// the `analyst` role. Assets that do not carry the CVE are skipped and
/// reported; if none of them carries it, the call is a 404.
pub async fn set_findings_bulk(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<SetFindingsBulkRequest>,
) -> Result<Json<BulkOutcome>, (StatusCode, String)> {
    auth.require(argus_core::tenant::Role::Analyst)?;

    let (cve_id, status, note) = validate(&req.cve_id, &req.status, req.note)?;
    if req.asset_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "asset_ids must not be empty".into(),
        ));
    }
    if req.asset_ids.len() > MAX_BULK {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("asset_ids exceeds {MAX_BULK} entries"),
        ));
    }

    // Same existence rule as the single route, applied per asset: decisions
    // attach only to observed (asset, CVE) pairs. Requested assets without
    // the CVE are skipped, not failed — the console may be one poll behind.
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
    let carries_cve: std::collections::HashSet<Uuid> = assets
        .iter()
        .filter(|a| a.vulnerabilities.iter().any(|v| v.cve_id == cve_id))
        .map(|a| a.asset.id.0)
        .collect();
    let mut seen = std::collections::HashSet::new();
    let mut existing = Vec::new();
    let mut skipped = Vec::new();
    for id in req.asset_ids {
        if !seen.insert(id) {
            continue;
        }
        if carries_cve.contains(&id) {
            existing.push(id);
        } else {
            skipped.push(id);
        }
    }
    if existing.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "none of the assets carries this CVE".into(),
        ));
    }

    let updated_by = auth.email.clone().unwrap_or_else(|| "api-key".to_owned());
    if status == "open" {
        state
            .store
            .clear_finding_statuses_bulk(auth.tenant_id, &existing, cve_id)
            .await
            .map_err(store_error)?;
    } else {
        state
            .store
            .set_finding_statuses_bulk(
                auth.tenant_id,
                &existing,
                cve_id,
                status,
                &note,
                &updated_by,
            )
            .await
            .map_err(store_error)?;
    }

    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "finding.bulk_status",
            serde_json::json!({
                "cve_id": cve_id,
                "status": status,
                "updated": existing.len(),
                "skipped": skipped.len(),
            }),
        )
        .await;
    Ok(Json(BulkOutcome {
        updated: existing.len(),
        skipped,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use argus_core::tenant::Role;
    use argus_core::{
        Asset, AssetId, AssetType, Criticality, Exposure, Fingerprint, Interface, RiskBand,
        RiskScore, Severity, Vulnerability,
    };
    use time::OffsetDateTime;

    use crate::auth::{AuthKeys, LoginLimiter};
    use crate::seed::ScoredAsset;
    use crate::store::{IngestLocks, Store};

    use super::*;

    fn vuln(cve: &str) -> Vulnerability {
        Vulnerability {
            cve_id: cve.to_owned(),
            cvss: None,
            epss: None,
            kev: false,
            severity: Severity::High,
        }
    }

    fn asset(host: &str, vulns: Vec<Vulnerability>) -> ScoredAsset {
        ScoredAsset {
            asset: Asset {
                id: AssetId::new(),
                asset_type: AssetType::It,
                criticality: Criticality::Medium,
                exposure: Exposure::Internal,
                fingerprint: Fingerprint::default(),
                interfaces: vec![Interface {
                    mac: None,
                    ip: None,
                    vlan: None,
                    hostname: Some(host.to_owned()),
                }],
                first_seen: OffsetDateTime::UNIX_EPOCH,
                last_seen: OffsetDateTime::UNIX_EPOCH,
            },
            services: Vec::new(),
            vulnerabilities: vulns,
            risk: RiskScore {
                value: 50.0,
                band: RiskBand::from_value(50.0),
            },
            overrides: crate::seed::AssetOverrides::default(),
        }
    }

    fn app_state(store: Store) -> AppState {
        AppState {
            store,
            keys: AuthKeys::from_secret(b"test-secret"),
            limiter: Arc::new(LoginLimiter::default()),
            signup_enabled: false,
            ingest_locks: IngestLocks::default(),
            intel: argus_vuln::intel::IntelCache::new(None),
        }
    }

    fn auth(tenant_id: Uuid, role: Role) -> AuthContext {
        AuthContext {
            tenant_id,
            user_id: None,
            email: Some("analyst@argus.local".to_owned()),
            role,
        }
    }

    fn bulk_req(cve: &str, asset_ids: Vec<Uuid>, status: &str) -> SetFindingsBulkRequest {
        SetFindingsBulkRequest {
            cve_id: cve.to_owned(),
            asset_ids,
            status: status.to_owned(),
            note: Some("maintenance window".to_owned()),
        }
    }

    #[tokio::test]
    async fn bulk_sets_carrying_assets_and_skips_the_rest() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        let hit_a = asset("web-01", vec![vuln("CVE-2024-1")]);
        let hit_b = asset("web-02", vec![vuln("CVE-2024-1")]);
        let miss = asset("db-01", vec![vuln("CVE-2024-2")]);
        for a in [&hit_a, &hit_b, &miss] {
            store.upsert(tenant, a).await.unwrap();
        }

        let ids = vec![
            hit_a.asset.id.0,
            hit_b.asset.id.0,
            miss.asset.id.0,
            hit_a.asset.id.0, // duplicate — must not double-count
        ];
        let Json(outcome) = set_findings_bulk(
            auth(tenant, Role::Analyst),
            State(app_state(store.clone())),
            Json(bulk_req("CVE-2024-1", ids, "acknowledged")),
        )
        .await
        .unwrap();

        assert_eq!(outcome.updated, 2);
        assert_eq!(outcome.skipped, vec![miss.asset.id.0]);
        let statuses = store.list_finding_statuses(tenant).await.unwrap();
        assert_eq!(statuses.len(), 2);
        assert!(statuses
            .iter()
            .all(|s| s.status == "acknowledged" && s.note == "maintenance window"));
    }

    #[tokio::test]
    async fn bulk_open_clears_existing_decisions() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        let a = asset("web-01", vec![vuln("CVE-2024-1")]);
        let b = asset("web-02", vec![vuln("CVE-2024-1")]);
        for x in [&a, &b] {
            store.upsert(tenant, x).await.unwrap();
        }
        let ids = vec![a.asset.id.0, b.asset.id.0];

        let state = app_state(store.clone());
        let Json(set) = set_findings_bulk(
            auth(tenant, Role::Analyst),
            State(state.clone()),
            Json(bulk_req("CVE-2024-1", ids.clone(), "resolved")),
        )
        .await
        .unwrap();
        assert_eq!(set.updated, 2);
        assert_eq!(store.list_finding_statuses(tenant).await.unwrap().len(), 2);

        let Json(outcome) = set_findings_bulk(
            auth(tenant, Role::Analyst),
            State(state),
            Json(bulk_req("CVE-2024-1", ids, "open")),
        )
        .await
        .unwrap();
        assert_eq!(outcome.updated, 2);
        assert!(store
            .list_finding_statuses(tenant)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn bulk_with_no_carrying_asset_is_a_404() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        let a = asset("web-01", vec![vuln("CVE-2024-2")]);
        store.upsert(tenant, &a).await.unwrap();

        let err = set_findings_bulk(
            auth(tenant, Role::Analyst),
            State(app_state(store)),
            Json(bulk_req("CVE-2024-1", vec![a.asset.id.0], "acknowledged")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bulk_requires_the_analyst_role() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        let a = asset("web-01", vec![vuln("CVE-2024-1")]);
        store.upsert(tenant, &a).await.unwrap();

        let err = set_findings_bulk(
            auth(tenant, Role::Viewer),
            State(app_state(store)),
            Json(bulk_req("CVE-2024-1", vec![a.asset.id.0], "acknowledged")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}

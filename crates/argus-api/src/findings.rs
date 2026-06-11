//! `POST /api/findings` — analyst triage for one (asset, CVE) finding.
//!
//! IR workflow v1: a finding is `open` by default; analysts set
//! `acknowledged` / `resolved` / `false_positive` (with an optional note),
//! or `open` to clear the decision. The status is keyed by the stable asset
//! id + CVE id, so it survives re-scans, and it is triage metadata only —
//! the computed risk score is deliberately not altered (an accepted risk is
//! still a risk; the console shows both).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::vulns::FindingState;
use crate::{store_error, AppState};

/// Longest accepted analyst note.
const MAX_NOTE: usize = 500;

/// Valid triage statuses (besides `open`, which clears the row).
const STATUSES: &[&str] = &["acknowledged", "resolved", "false_positive"];

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

    let cve_id = req.cve_id.trim();
    if cve_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "cve_id must not be empty".into()));
    }
    let note = req.note.unwrap_or_default().trim().to_owned();
    if note.chars().count() > MAX_NOTE {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("note exceeds {MAX_NOTE} characters"),
        ));
    }
    let status = req.status.trim();
    if status != "open" && !STATUSES.contains(&status) {
        return Err((
            StatusCode::BAD_REQUEST,
            "status must be one of: open, acknowledged, resolved, false_positive".into(),
        ));
    }

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

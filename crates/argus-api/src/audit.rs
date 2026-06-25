//! `GET /api/audit` — the tenant's admin-action audit trail (newest first).
//!
//! The trail is written on privileged actions (login, user / API-key / webhook
//! changes, scans) but had no read path; a school (DSGVO) needs to be able to
//! see *who did what, when*. Admin-only, since it exposes those actions.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use argus_core::tenant::Role;

use crate::auth::AuthContext;
use crate::db::AuditEntry;
use crate::{store_error, AppState};

/// Default number of trail entries returned.
const DEFAULT_LIMIT: i64 = 200;
/// Cap, so a request can't pull an unbounded trail.
const MAX_LIMIT: i64 = 1000;

/// `?limit=` — how many entries to return (clamped to `1..=1000`, default 200).
#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
}

/// The tenant's audit trail, newest first. Requires the `admin` role.
pub async fn get_audit(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let entries = state
        .store
        .list_audit(auth.tenant_id, limit)
        .await
        .map_err(store_error)?;
    Ok(Json(entries))
}

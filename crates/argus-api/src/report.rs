//! `GET /api/report` — a point-in-time exposure report for the caller's
//! tenant (executive summary, inventory, risk, vulnerabilities, activity,
//! monitoring coverage). Pure derivation lives in `argus-report`; this module
//! only loads the tenant's data and maps it into the builder's input facts.

use argus_report::{AssetFacts, EventFacts, ExposureReport, MonitorFacts};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::auth::AuthContext;
use crate::monitor;
use crate::{store_error, AppState};

/// Events fetched as the activity basis. Generous compared to the console's
/// feed (max 200) so period counts stay meaningful; events are pruned at 90
/// days anyway, which bounds the result regardless.
const EVENT_BASIS: i64 = 2000;

#[derive(Deserialize)]
pub struct ReportQuery {
    /// Reporting period in days (default 30, clamped to `1..=90` — the
    /// event retention window).
    days: Option<u32>,
}

/// Build the tenant's exposure report. Readable by every authenticated role.
pub async fn get_report(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<ReportQuery>,
) -> Result<Json<ExposureReport>, (StatusCode, String)> {
    let days = query.days.unwrap_or(30).clamp(1, 90);

    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
    let events = state
        .store
        .list_events(auth.tenant_id, EVENT_BASIS)
        .await
        .map_err(store_error)?;
    let monitor_row = state
        .store
        .get_monitor(auth.tenant_id)
        .await
        .map_err(store_error)?;

    let asset_facts: Vec<AssetFacts> = assets
        .iter()
        .map(|a| AssetFacts {
            name: monitor::asset_name(a),
            ip: a
                .asset
                .interfaces
                .iter()
                .find_map(|i| i.ip.map(|ip| ip.to_string())),
            asset_type: a.asset.asset_type,
            criticality: a.asset.criticality,
            exposure: a.asset.exposure,
            risk: a.risk,
            vulns: a.vulnerabilities.clone(),
            first_seen: a.asset.first_seen,
            last_seen: a.asset.last_seen,
        })
        .collect();
    let event_facts: Vec<EventFacts> = events
        .into_iter()
        .map(|e| EventFacts {
            kind: e.kind,
            at: e.created_at,
        })
        .collect();
    let monitor_facts = monitor_row.map(|m| MonitorFacts {
        enabled: m.enabled,
        interval_minutes: m.interval_minutes,
        target: m.target,
        last_run_at: m.last_run_at,
    });

    Ok(Json(argus_report::build(
        &asset_facts,
        &event_facts,
        monitor_facts.as_ref(),
        OffsetDateTime::now_utc(),
        days,
    )))
}

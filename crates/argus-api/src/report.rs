//! `GET /api/report` — a point-in-time exposure report for the caller's
//! tenant (executive summary, inventory, risk, vulnerabilities, activity,
//! monitoring coverage). Pure derivation lives in `argus-report`; this module
//! only loads the tenant's data and maps it into the builder's input facts.

use argus_policy::{AdvisoryLevel, PolicyAsset};
use argus_report::{
    AdvisoryFact, AdvisoryUrgency, AssetFacts, EventFacts, ExposureReport, MonitorFacts,
};
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
            device_role: a.asset.fingerprint.role(),
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

    // Run the segmentation/exposure rules and feed them into the action plan,
    // so "fix these this week" spans both vulnerabilities and zoning findings.
    let policy_facts: Vec<PolicyAsset> = assets
        .iter()
        .map(|a| PolicyAsset {
            name: monitor::asset_name(a),
            ip: a.asset.interfaces.iter().find_map(|i| i.ip),
            asset_type: a.asset.asset_type,
            criticality: a.asset.criticality,
            exposure: a.asset.exposure,
            open_ports: a.services.iter().map(|s| s.port).collect(),
            has_kev: a.vulnerabilities.iter().any(|v| v.kev),
            os: a.asset.fingerprint.os.clone(),
            device_role: a.asset.fingerprint.role(),
        })
        .collect();
    let advisory_facts: Vec<AdvisoryFact> = argus_policy::evaluate(&policy_facts)
        .into_iter()
        .map(|adv| AdvisoryFact {
            rule: adv.rule.to_owned(),
            level: match adv.level {
                AdvisoryLevel::Critical => AdvisoryUrgency::Critical,
                AdvisoryLevel::High => AdvisoryUrgency::High,
                AdvisoryLevel::Medium => AdvisoryUrgency::Medium,
                AdvisoryLevel::Low => AdvisoryUrgency::Low,
            },
            title: adv.title,
            rationale: adv.rationale,
            recommendation: adv.recommendation,
            affected: adv.affected.into_iter().map(|x| x.name).collect(),
        })
        .collect();

    Ok(Json(argus_report::build(
        &asset_facts,
        &advisory_facts,
        &event_facts,
        monitor_facts.as_ref(),
        OffsetDateTime::now_utc(),
        days,
    )))
}

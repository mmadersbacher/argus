//! Continuous monitoring: change detection between scans, the change-event
//! feed (`GET /api/events`), and the per-tenant monitor configuration
//! (`GET`/`POST /api/monitor`) consumed by the background scheduler.
//!
//! Change detection compares the previously stored [`ScoredAsset`] (by
//! correlation key) against the freshly scanned one and emits typed events:
//! `asset.new`, `services.changed`, `vulns.changed`, and `risk.changed`
//! (band transitions only — raw `f32` jitter is not a change).

use std::collections::{BTreeMap, BTreeSet};

use argus_core::tenant::Role;
use argus_core::Protocol;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::auth::AuthContext;
use crate::db::{EventRow, MonitorRow};
use crate::seed::ScoredAsset;
use crate::{store_error, AppState};

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

/// A detected change on one asset, ready to be persisted as an event.
#[derive(Debug)]
pub struct ChangeEvent {
    /// Event kind: `asset.new`, `services.changed`, `vulns.changed`,
    /// or `risk.changed`.
    pub kind: &'static str,
    /// Kind-specific payload (the API contract's `detail` object).
    pub detail: serde_json::Value,
}

/// Diff the previously stored asset against a fresh scan result.
///
/// `old = None` (first sighting) yields a single `asset.new` event. Otherwise:
/// services are compared by port, vulnerabilities by CVE-id set, and risk only
/// by band — a score fluctuation within the same band is not a change.
#[must_use]
pub fn diff(old: Option<&ScoredAsset>, new: &ScoredAsset) -> Vec<ChangeEvent> {
    let Some(old) = old else {
        return vec![ChangeEvent {
            kind: "asset.new",
            detail: serde_json::json!({
                "risk": new.risk.value,
                "band": new.risk.band,
                "services": new.services.len(),
            }),
        }];
    };
    let mut events = Vec::new();

    // Services, compared by (port, protocol) so tcp/53 and udp/53 are distinct
    // entries (sorted for deterministic payloads). The wire payload stays
    // {port, product} — protocol is part of the key, not the JSON.
    let old_ports: BTreeMap<(u16, Protocol), Option<&str>> = old
        .services
        .iter()
        .map(|s| ((s.port, s.protocol), s.product.as_deref()))
        .collect();
    let new_ports: BTreeMap<(u16, Protocol), Option<&str>> = new
        .services
        .iter()
        .map(|s| ((s.port, s.protocol), s.product.as_deref()))
        .collect();
    let added: Vec<serde_json::Value> = new_ports
        .iter()
        .filter(|(key, _)| !old_ports.contains_key(key))
        .map(|(&(port, _), &product)| service_entry(port, product))
        .collect();
    let removed: Vec<serde_json::Value> = old_ports
        .iter()
        .filter(|(key, _)| !new_ports.contains_key(key))
        .map(|(&(port, _), &product)| service_entry(port, product))
        .collect();
    if !added.is_empty() || !removed.is_empty() {
        events.push(ChangeEvent {
            kind: "services.changed",
            detail: serde_json::json!({ "added": added, "removed": removed }),
        });
    }

    // Vulnerabilities, compared as CVE-id sets.
    let old_cves: BTreeSet<&str> = old
        .vulnerabilities
        .iter()
        .map(|v| v.cve_id.as_str())
        .collect();
    let new_cves: BTreeSet<&str> = new
        .vulnerabilities
        .iter()
        .map(|v| v.cve_id.as_str())
        .collect();
    let added_cves: Vec<&str> = new_cves.difference(&old_cves).copied().collect();
    let removed_cves: Vec<&str> = old_cves.difference(&new_cves).copied().collect();
    if !added_cves.is_empty() || !removed_cves.is_empty() {
        let kev_added = new
            .vulnerabilities
            .iter()
            .filter(|v| v.kev && !old_cves.contains(v.cve_id.as_str()))
            .count();
        events.push(ChangeEvent {
            kind: "vulns.changed",
            detail: serde_json::json!({
                "added": added_cves,
                "removed": removed_cves,
                "kev_added": kev_added,
            }),
        });
    }

    // Risk: only a band transition counts as a change.
    if old.risk.band != new.risk.band {
        events.push(ChangeEvent {
            kind: "risk.changed",
            detail: serde_json::json!({
                "old": old.risk.value,
                "new": new.risk.value,
                "old_band": old.risk.band,
                "new_band": new.risk.band,
            }),
        });
    }
    events
}

/// One service as embedded in a `services.changed` payload.
fn service_entry(port: u16, product: Option<&str>) -> serde_json::Value {
    serde_json::json!({ "port": port, "product": product })
}

/// Carry observation history from the previously stored asset onto a rescan
/// result: keep the original `id` and `first_seen` (each discovery run mints a
/// fresh `AssetId`, so without this the asset's UUID would rotate every run and
/// `GET /api/assets/{id}` would 404), and stamp `last_seen` to now.
pub fn carry_forward(old: &ScoredAsset, new: &mut ScoredAsset) {
    new.asset.id = old.asset.id;
    new.asset.first_seen = old.asset.first_seen;
    new.asset.last_seen = OffsetDateTime::now_utc();
    // Business context is an analyst decision, not a discovery output:
    // overrides survive the re-scan and win over the re-derived values.
    new.overrides = old.overrides;
    new.overrides.apply(&mut new.asset);
}

/// Human-readable asset label for the event feed: hostname of the first
/// interface that has one, else the first IP, else the shortened asset id.
#[must_use]
pub fn asset_name(asset: &ScoredAsset) -> String {
    asset
        .asset
        .interfaces
        .iter()
        .find_map(|i| i.hostname.clone())
        .or_else(|| {
            asset
                .asset
                .interfaces
                .iter()
                .find_map(|i| i.ip.map(|ip| ip.to_string()))
        })
        .unwrap_or_else(|| {
            let id = asset.asset.id.to_string();
            id[..8].to_owned()
        })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Query parameters for `GET /api/events`.
#[derive(Deserialize)]
pub struct EventsQuery {
    /// Max number of events to return (default 50, clamped to `1..=200`).
    limit: Option<i64>,
}

/// `GET /api/events?limit=50` — the tenant's change events, newest first.
/// Readable by every authenticated role.
pub async fn list_events(
    auth: AuthContext,
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Vec<EventRow>>, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    state
        .store
        .list_events(auth.tenant_id, limit)
        .await
        .map(Json)
        .map_err(store_error)
}

/// `GET /api/monitor` — the tenant's monitor config, or `{"configured": false}`
/// when none was ever saved. Readable by every authenticated role.
pub async fn get_monitor(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let monitor = state
        .store
        .get_monitor(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(monitor.as_ref().map_or_else(
        || serde_json::json!({ "configured": false }),
        monitor_view,
    )))
}

/// `POST /api/monitor` request body.
#[derive(Deserialize)]
pub struct MonitorRequest {
    /// Scan target (ip / cidr / range), validated via the discovery expander.
    target: String,
    /// Scan cadence in minutes, `1..=1440`.
    interval_minutes: i32,
    /// Whether scheduled scans run (default `true`).
    #[serde(default = "default_enabled")]
    enabled: bool,
    /// Privileged deep scan engine (default `false`).
    #[serde(default)]
    deep: bool,
}

const fn default_enabled() -> bool {
    true
}

/// `POST /api/monitor` — create or replace the tenant's monitor (one per
/// tenant, a deliberate v1 decision). Requires the `analyst` role.
pub async fn set_monitor(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<MonitorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    auth.require(Role::Analyst)?;
    let target = req.target.trim();
    let ips =
        argus_discovery::expand(target).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    crate::scan::reject_private_targets(&ips, state.scan_allow_private)?;
    if !(1..=1440).contains(&req.interval_minutes) {
        return Err((
            StatusCode::BAD_REQUEST,
            "interval_minutes must be between 1 and 1440".to_owned(),
        ));
    }
    state
        .store
        .set_monitor(
            auth.tenant_id,
            target,
            req.interval_minutes,
            req.enabled,
            req.deep,
        )
        .await
        .map_err(store_error)?;
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "monitor.config",
            serde_json::json!({
                "target": target,
                "interval_minutes": req.interval_minutes,
                "enabled": req.enabled,
                "deep": req.deep,
            }),
        )
        .await;
    // Re-read so the response reflects exactly what is stored (incl. any
    // preserved last_run_at).
    let saved = state
        .store
        .get_monitor(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(saved.as_ref().map_or_else(
        || serde_json::json!({ "configured": false }),
        monitor_view,
    )))
}

/// The `GET /api/monitor` response shape for a configured monitor.
fn monitor_view(m: &MonitorRow) -> serde_json::Value {
    serde_json::json!({
        "configured": true,
        "target": m.target,
        "interval_minutes": m.interval_minutes,
        "enabled": m.enabled,
        "deep": m.deep,
        "last_run_at": m.last_run_at.and_then(|t| t.format(&Rfc3339).ok()),
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use argus_core::{
        Asset, AssetId, AssetType, Confidence, Criticality, Exposure, Fingerprint, Interface,
        Protocol, RiskBand, RiskScore, Service, Severity, Vulnerability,
    };

    use super::*;

    fn scored(
        services: &[(u16, Option<&str>)],
        vulns: &[(&str, bool)],
        risk_value: f32,
    ) -> ScoredAsset {
        let tcp: Vec<(u16, Protocol, Option<&str>)> = services
            .iter()
            .map(|&(port, product)| (port, Protocol::Tcp, product))
            .collect();
        scored_proto(&tcp, vulns, risk_value)
    }

    fn scored_proto(
        services: &[(u16, Protocol, Option<&str>)],
        vulns: &[(&str, bool)],
        risk_value: f32,
    ) -> ScoredAsset {
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
            services: services
                .iter()
                .map(|&(port, protocol, product)| Service {
                    port,
                    protocol,
                    product: product.map(str::to_owned),
                    banner: None,
                    cpe: None,
                })
                .collect(),
            vulnerabilities: vulns
                .iter()
                .map(|&(cve_id, kev)| Vulnerability {
                    cve_id: cve_id.to_owned(),
                    cvss: None,
                    epss: None,
                    kev,
                    severity: Severity::High,
                    match_confidence: Confidence::High,
                })
                .collect(),
            risk: RiskScore {
                value: risk_value,
                band: RiskBand::from_value(risk_value),
                confidence: Confidence::High,
            },
            overrides: crate::seed::AssetOverrides::default(),
        }
    }

    #[test]
    fn new_asset_emits_asset_new_with_contract_shape() {
        let new = scored(&[(22, Some("OpenSSH 8.9")), (443, None)], &[], 72.5);
        let events = diff(None, &new);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "asset.new");
        let detail = &events[0].detail;
        assert!((detail["risk"].as_f64().unwrap() - 72.5).abs() < 1e-6);
        assert_eq!(detail["band"], "high");
        assert_eq!(detail["services"], 2);
    }

    #[test]
    fn unchanged_asset_emits_nothing() {
        let old = scored(&[(22, Some("OpenSSH 8.9"))], &[("CVE-2024-1", false)], 50.0);
        let new = scored(&[(22, Some("OpenSSH 8.9"))], &[("CVE-2024-1", false)], 50.0);
        assert!(diff(Some(&old), &new).is_empty());
    }

    #[test]
    fn service_add_and_remove_are_reported_by_port() {
        let old = scored(&[(21, None), (22, Some("OpenSSH 8.9"))], &[], 30.0);
        let new = scored(
            &[(22, Some("OpenSSH 8.9")), (443, Some("nginx 1.24"))],
            &[],
            30.0,
        );
        let events = diff(Some(&old), &new);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "services.changed");
        let detail = &events[0].detail;
        assert_eq!(
            detail["added"],
            serde_json::json!([{ "port": 443, "product": "nginx 1.24" }])
        );
        // Removed FTP had no product fingerprint — product must be null.
        assert_eq!(
            detail["removed"],
            serde_json::json!([{ "port": 21, "product": null }])
        );
    }

    #[test]
    fn vuln_changes_count_new_kev_entries() {
        let old = scored(&[], &[("CVE-2020-1", false), ("CVE-2020-2", true)], 50.0);
        let new = scored(
            &[],
            &[
                ("CVE-2020-2", true), // pre-existing KEV: not counted again
                ("CVE-2024-1234", true),
                ("CVE-2024-9999", false),
            ],
            50.0,
        );
        let events = diff(Some(&old), &new);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "vulns.changed");
        let detail = &events[0].detail;
        assert_eq!(
            detail["added"],
            serde_json::json!(["CVE-2024-1234", "CVE-2024-9999"])
        );
        assert_eq!(detail["removed"], serde_json::json!(["CVE-2020-1"]));
        assert_eq!(detail["kev_added"], 1);
    }

    #[test]
    fn risk_band_transition_is_reported() {
        let old = scored(&[], &[], 45.0);
        let new = scored(&[], &[], 80.1);
        let events = diff(Some(&old), &new);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "risk.changed");
        let detail = &events[0].detail;
        assert!((detail["old"].as_f64().unwrap() - 45.0).abs() < 1e-6);
        assert_eq!(detail["old_band"], "medium");
        assert_eq!(detail["new_band"], "critical");
    }

    #[test]
    fn risk_jitter_within_a_band_is_not_a_change() {
        let old = scored(&[], &[], 45.0);
        let new = scored(&[], &[], 47.3);
        assert!(diff(Some(&old), &new).is_empty());
    }

    #[test]
    fn carry_forward_preserves_id_first_seen_and_bumps_last_seen() {
        let old = scored(&[], &[], 10.0); // first_seen = UNIX_EPOCH
        let mut new = scored(&[], &[], 10.0);
        new.asset.first_seen = OffsetDateTime::now_utc();
        let old_id = old.asset.id;
        assert_ne!(new.asset.id, old_id); // each run mints a fresh id
        carry_forward(&old, &mut new);
        // Identity continuity: the stored UUID survives a rescan.
        assert_eq!(new.asset.id, old_id);
        assert_eq!(new.asset.first_seen, OffsetDateTime::UNIX_EPOCH);
        assert!(new.asset.last_seen > OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn carry_forward_reapplies_business_overrides() {
        let mut old = scored(&[], &[], 10.0);
        old.overrides.criticality = Some(Criticality::Critical);
        old.overrides.exposure = Some(Exposure::InternetFacing);
        // The rescan re-derived Medium/Internal; the override must win.
        let mut new = scored(&[], &[], 10.0);
        carry_forward(&old, &mut new);
        assert_eq!(new.overrides, old.overrides);
        assert_eq!(new.asset.criticality, Criticality::Critical);
        assert_eq!(new.asset.exposure, Exposure::InternetFacing);
    }

    #[test]
    fn same_port_different_protocol_services_are_tracked_separately() {
        // tcp/53 already present; the rescan adds udp/53. Keyed by port alone,
        // udp/53 would collapse into tcp/53 and the change would be missed.
        let old = scored_proto(&[(53, Protocol::Tcp, Some("dns-tcp"))], &[], 10.0);
        let new = scored_proto(
            &[
                (53, Protocol::Tcp, Some("dns-tcp")),
                (53, Protocol::Udp, Some("dns-udp")),
            ],
            &[],
            10.0,
        );
        let events = diff(Some(&old), &new);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "services.changed");
        // The new udp/53 is reported as added; nothing removed.
        assert_eq!(
            events[0].detail["added"],
            serde_json::json!([{ "port": 53, "product": "dns-udp" }])
        );
        assert_eq!(events[0].detail["removed"], serde_json::json!([]));

        // And dropping the udp side (back to tcp-only) is a removal.
        let back = diff(Some(&new), &old);
        assert_eq!(back.len(), 1);
        assert_eq!(
            back[0].detail["removed"],
            serde_json::json!([{ "port": 53, "product": "dns-udp" }])
        );
    }

    #[test]
    fn asset_name_prefers_hostname_then_ip_then_short_id() {
        let mut a = scored(&[], &[], 0.0);
        let short_id = a.asset.id.to_string()[..8].to_owned();
        assert_eq!(asset_name(&a), short_id);

        a.asset.interfaces.push(Interface {
            mac: None,
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            vlan: None,
            hostname: None,
        });
        assert_eq!(asset_name(&a), "10.0.0.5");

        a.asset.interfaces.push(Interface {
            mac: None,
            ip: None,
            vlan: None,
            hostname: Some("web-01".to_owned()),
        });
        assert_eq!(asset_name(&a), "web-01");
    }
}

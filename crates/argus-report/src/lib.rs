//! # argus-report
//!
//! Compliance / executive reporting: turn a tenant's scored inventory, change
//! history and monitoring state into a structured, point-in-time
//! [`ExposureReport`].
//!
//! The builder is pure and IO-free — callers (argus-api) load the data and
//! map it into the small `*Facts` input types; everything here is derivation,
//! which keeps the whole report unit-testable without a store or feeds.

use std::collections::HashMap;

use argus_core::{
    AssetType, Criticality, DeviceRole, Exposure, RiskBand, RiskScore, Severity, Vulnerability,
};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

pub mod action;
pub use action::{ActionEffort, ActionItem, ActionPriority, AdvisoryFact, AdvisoryUrgency};

/// Maximum rows in the top-risk-assets and top-CVE tables.
const TOP_LIMIT: usize = 10;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One asset, reduced to the facts the report consumes.
#[derive(Debug, Clone)]
pub struct AssetFacts {
    /// Display name (hostname > IP > id prefix, as shown in the console).
    pub name: String,
    /// Primary IP, if known.
    pub ip: Option<String>,
    /// Classified asset type.
    pub asset_type: AssetType,
    /// Typed device role (DC, camera, NAS, …) resolved from the fingerprint.
    pub device_role: DeviceRole,
    /// Business criticality.
    pub criticality: Criticality,
    /// Network exposure.
    pub exposure: Exposure,
    /// Composite risk score.
    pub risk: RiskScore,
    /// Correlated vulnerabilities.
    pub vulns: Vec<Vulnerability>,
    /// First sighting.
    pub first_seen: OffsetDateTime,
    /// Most recent sighting.
    pub last_seen: OffsetDateTime,
}

/// One change event, reduced to the facts the report consumes.
#[derive(Debug, Clone)]
pub struct EventFacts {
    /// Event kind (`asset.new`, `services.changed`, `vulns.changed`,
    /// `risk.changed`).
    pub kind: String,
    /// When the event was recorded.
    pub at: OffsetDateTime,
}

/// Monitoring configuration, reduced to the facts the report consumes.
#[derive(Debug, Clone)]
pub struct MonitorFacts {
    /// Whether scheduled scans are enabled.
    pub enabled: bool,
    /// Scan cadence in minutes.
    pub interval_minutes: i32,
    /// Scan target spec.
    pub target: String,
    /// When the monitor last started a run.
    pub last_run_at: Option<OffsetDateTime>,
}

// ---------------------------------------------------------------------------
// Report model
// ---------------------------------------------------------------------------

/// Severity of an executive-summary highlight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HighlightLevel {
    /// Needs action now.
    Critical,
    /// Needs attention.
    Warn,
    /// Context worth knowing.
    Info,
}

/// One executive-summary bullet.
#[derive(Debug, Clone, Serialize)]
pub struct Highlight {
    /// How urgent the highlight is.
    pub level: HighlightLevel,
    /// Human-readable statement.
    pub text: String,
}

/// Count per asset type.
#[derive(Debug, Clone, Serialize)]
pub struct TypeCount {
    /// Asset type.
    pub asset_type: AssetType,
    /// Number of assets.
    pub count: usize,
}

/// Count per device role.
#[derive(Debug, Clone, Serialize)]
pub struct RoleCount {
    /// Device role.
    pub role: DeviceRole,
    /// Number of assets.
    pub count: usize,
}

/// Count per business criticality.
#[derive(Debug, Clone, Serialize)]
pub struct CriticalityCount {
    /// Criticality level.
    pub criticality: Criticality,
    /// Number of assets.
    pub count: usize,
}

/// Count per risk band.
#[derive(Debug, Clone, Serialize)]
pub struct BandCount {
    /// Risk band.
    pub band: RiskBand,
    /// Number of assets.
    pub count: usize,
}

/// Inventory section: what is on the network.
#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    /// Total assets known.
    pub total: usize,
    /// Assets reachable from the internet.
    pub internet_facing: usize,
    /// Assets first seen within the reporting period.
    pub new_in_period: usize,
    /// Assets not seen within the reporting period.
    pub stale: usize,
    /// Breakdown by asset type (non-zero, largest first).
    pub by_type: Vec<TypeCount>,
    /// Breakdown by device role (non-zero, largest first).
    pub by_role: Vec<RoleCount>,
    /// Breakdown by criticality (most critical first, zeros included).
    pub by_criticality: Vec<CriticalityCount>,
}

/// One row of the top-risk-assets table.
#[derive(Debug, Clone, Serialize)]
pub struct TopAsset {
    /// Display name.
    pub name: String,
    /// Primary IP, if known.
    pub ip: Option<String>,
    /// Asset type.
    pub asset_type: AssetType,
    /// Business criticality.
    pub criticality: Criticality,
    /// Network exposure.
    pub exposure: Exposure,
    /// Composite risk.
    pub risk: RiskScore,
    /// Number of correlated CVEs.
    pub cves: usize,
    /// Number of KEV-listed CVEs.
    pub kev_cves: usize,
}

/// Risk section: how bad it is.
#[derive(Debug, Clone, Serialize)]
pub struct RiskPosture {
    /// Mean risk score across all assets.
    pub average: f32,
    /// Distribution across all five bands (worst first, zeros included).
    pub distribution: Vec<BandCount>,
    /// Highest-risk assets (at most [`TOP_LIMIT`]).
    pub top_assets: Vec<TopAsset>,
}

/// One row of the top-CVE table.
#[derive(Debug, Clone, Serialize)]
pub struct TopCve {
    /// CVE identifier.
    pub cve_id: String,
    /// Worst observed severity.
    pub severity: Severity,
    /// Highest observed CVSS base score.
    pub cvss: Option<f32>,
    /// Highest observed EPSS score.
    pub epss: Option<f32>,
    /// Whether the CVE is on the CISA KEV catalog.
    pub kev: bool,
    /// Number of affected assets.
    pub affected: usize,
}

/// Vulnerability section: what is exploitable.
#[derive(Debug, Clone, Serialize)]
pub struct VulnPosture {
    /// Unique CVEs across the inventory.
    pub unique_cves: usize,
    /// Unique CVEs on the CISA KEV catalog.
    pub kev_cves: usize,
    /// Unique critical-severity CVEs.
    pub critical_cves: usize,
    /// Unique high-severity CVEs.
    pub high_cves: usize,
    /// Assets carrying at least one KEV-listed CVE.
    pub assets_with_kev: usize,
    /// Most urgent CVEs (KEV first, then EPSS, then CVSS; at most
    /// [`TOP_LIMIT`]).
    pub top_cves: Vec<TopCve>,
}

/// Activity section: what changed in the period.
#[derive(Debug, Clone, Serialize)]
pub struct Activity {
    /// All change events in the period.
    pub events_in_period: usize,
    /// `asset.new` events.
    pub new_assets: usize,
    /// `services.changed` events.
    pub service_changes: usize,
    /// `vulns.changed` events.
    pub vuln_changes: usize,
    /// `risk.changed` events (band transitions).
    pub risk_changes: usize,
}

/// Monitoring section: how fresh the picture is.
#[derive(Debug, Clone, Serialize)]
pub struct Monitoring {
    /// Whether a monitor was ever configured.
    pub configured: bool,
    /// Whether scheduled scans are enabled.
    pub enabled: bool,
    /// Scan cadence in minutes, when configured.
    pub interval_minutes: Option<i32>,
    /// Scan target spec, when configured.
    pub target: Option<String>,
    /// When the monitor last started a run.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_run_at: Option<OffsetDateTime>,
    /// Share of assets seen within the period, `0.0..=100.0`.
    pub coverage_percent: f32,
}

/// A point-in-time exposure report for one tenant.
#[derive(Debug, Clone, Serialize)]
pub struct ExposureReport {
    /// When the report was generated.
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    /// Reporting period in days (activity, freshness and "new" windows).
    pub period_days: u32,
    /// Executive summary (worst first).
    pub highlights: Vec<Highlight>,
    /// "Fix these this week" — the ranked, actionable remediation plan.
    pub action_plan: Vec<ActionItem>,
    /// Inventory section.
    pub inventory: Inventory,
    /// Risk section.
    pub risk: RiskPosture,
    /// Vulnerability section.
    pub vulnerabilities: VulnPosture,
    /// Activity section.
    pub activity: Activity,
    /// Monitoring section.
    pub monitoring: Monitoring,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build an [`ExposureReport`] from the tenant's facts.
///
/// `period_days` bounds the activity window and the "new" / "stale" /
/// coverage derivations. Events older than the period are ignored even if the
/// caller passes them.
#[must_use]
#[allow(clippy::cast_precision_loss)] // counts -> percentages / averages
pub fn build(
    assets: &[AssetFacts],
    advisories: &[AdvisoryFact],
    events: &[EventFacts],
    monitor: Option<&MonitorFacts>,
    now: OffsetDateTime,
    period_days: u32,
) -> ExposureReport {
    let cutoff = now - Duration::days(i64::from(period_days));

    ExposureReport {
        generated_at: now,
        period_days,
        highlights: Vec::new(), // filled below, after the sections exist
        action_plan: action::action_plan(assets, advisories),
        inventory: inventory(assets, cutoff),
        risk: risk_posture(assets),
        vulnerabilities: vuln_posture(assets),
        activity: activity(events, cutoff),
        monitoring: monitoring(assets, monitor, cutoff),
    }
    .with_highlights()
}

impl ExposureReport {
    /// Derive the executive summary from the already-built sections.
    fn with_highlights(mut self) -> Self {
        let mut highlights = Vec::new();
        let critical_band = self
            .risk
            .distribution
            .iter()
            .find(|b| b.band == RiskBand::Critical)
            .map_or(0, |b| b.count);

        if self.vulnerabilities.assets_with_kev > 0 {
            highlights.push(Highlight {
                level: HighlightLevel::Critical,
                text: format!(
                    "{} asset(s) carry {} CVE(s) listed in the CISA Known Exploited \
                     Vulnerabilities catalog — prioritize remediation.",
                    self.vulnerabilities.assets_with_kev, self.vulnerabilities.kev_cves
                ),
            });
        }
        if critical_band > 0 {
            highlights.push(Highlight {
                level: HighlightLevel::Critical,
                text: format!("{critical_band} asset(s) sit in the Critical risk band."),
            });
        }
        if self.inventory.internet_facing > 0 {
            highlights.push(Highlight {
                level: HighlightLevel::Warn,
                text: format!(
                    "{} asset(s) are reachable from the internet.",
                    self.inventory.internet_facing
                ),
            });
        }
        if !self.monitoring.configured || !self.monitoring.enabled {
            highlights.push(Highlight {
                level: HighlightLevel::Warn,
                text: "Continuous monitoring is not active — the inventory only updates on \
                       manual scans."
                    .to_owned(),
            });
        }
        if self.inventory.stale > 0 {
            highlights.push(Highlight {
                level: HighlightLevel::Warn,
                text: format!(
                    "{} asset(s) were not seen within the last {} days.",
                    self.inventory.stale, self.period_days
                ),
            });
        }
        if self.inventory.new_in_period > 0 {
            highlights.push(Highlight {
                level: HighlightLevel::Info,
                text: format!(
                    "{} new asset(s) discovered in the last {} days.",
                    self.inventory.new_in_period, self.period_days
                ),
            });
        }
        if self.activity.risk_changes > 0 {
            highlights.push(Highlight {
                level: HighlightLevel::Info,
                text: format!(
                    "{} risk-band change(s) recorded in the period.",
                    self.activity.risk_changes
                ),
            });
        }
        if highlights.is_empty() {
            highlights.push(Highlight {
                level: HighlightLevel::Info,
                text: "No KEV exposure, no critical-risk assets and no notable changes in the \
                       period."
                    .to_owned(),
            });
        }
        self.highlights = highlights;
        self
    }
}

fn inventory(assets: &[AssetFacts], cutoff: OffsetDateTime) -> Inventory {
    // Largest first; ties keep declaration order (sort is stable). The variant
    // lists come from `AssetType::ALL` / `Criticality::ALL` so a new core
    // variant can never be silently dropped from the report (see the core
    // `all_covers_every_variant` guard).
    let mut by_type: Vec<TypeCount> = AssetType::ALL
        .into_iter()
        .map(|asset_type| TypeCount {
            asset_type,
            count: assets.iter().filter(|a| a.asset_type == asset_type).count(),
        })
        .filter(|t| t.count > 0)
        .collect();
    by_type.sort_by_key(|t| std::cmp::Reverse(t.count));

    // Same shape as by_type, driven by DeviceRole::ALL so a new role can never
    // be silently dropped (the core `all_covers_every_variant` guard enforces it).
    let mut by_role: Vec<RoleCount> = DeviceRole::ALL
        .into_iter()
        .map(|role| RoleCount {
            role,
            count: assets.iter().filter(|a| a.device_role == role).count(),
        })
        .filter(|r| r.count > 0)
        .collect();
    by_role.sort_by_key(|r| std::cmp::Reverse(r.count));

    // `ALL` is ascending (`Low`..`Critical`); the report shows worst-first.
    let by_criticality = Criticality::ALL
        .into_iter()
        .rev()
        .map(|criticality| CriticalityCount {
            criticality,
            count: assets
                .iter()
                .filter(|a| a.criticality == criticality)
                .count(),
        })
        .collect();

    Inventory {
        total: assets.len(),
        internet_facing: assets
            .iter()
            .filter(|a| a.exposure == Exposure::InternetFacing)
            .count(),
        new_in_period: assets.iter().filter(|a| a.first_seen >= cutoff).count(),
        stale: assets.iter().filter(|a| a.last_seen < cutoff).count(),
        by_type,
        by_role,
        by_criticality,
    }
}

#[allow(clippy::cast_precision_loss)]
fn risk_posture(assets: &[AssetFacts]) -> RiskPosture {
    let average = if assets.is_empty() {
        0.0
    } else {
        assets.iter().map(|a| a.risk.value).sum::<f32>() / assets.len() as f32
    };

    // `ALL` is ascending (`Info`..`Critical`); the distribution shows worst-first.
    let distribution = RiskBand::ALL
        .into_iter()
        .rev()
        .map(|band| BandCount {
            band,
            count: assets.iter().filter(|a| a.risk.band == band).count(),
        })
        .collect();

    let mut ranked: Vec<&AssetFacts> = assets.iter().collect();
    ranked.sort_by(|x, y| {
        y.risk
            .value
            .partial_cmp(&x.risk.value)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| x.name.cmp(&y.name))
    });
    let top_assets = ranked
        .into_iter()
        .take(TOP_LIMIT)
        .map(|a| TopAsset {
            name: a.name.clone(),
            ip: a.ip.clone(),
            asset_type: a.asset_type,
            criticality: a.criticality,
            exposure: a.exposure,
            risk: a.risk,
            cves: a.vulns.len(),
            kev_cves: a.vulns.iter().filter(|v| v.kev).count(),
        })
        .collect();

    RiskPosture {
        average,
        distribution,
        top_assets,
    }
}

/// Merged view of one CVE across assets while aggregating.
struct CveAggregate {
    severity: Severity,
    cvss: Option<f32>,
    epss: Option<f32>,
    kev: bool,
    affected: usize,
}

fn vuln_posture(assets: &[AssetFacts]) -> VulnPosture {
    let mut merged: HashMap<&str, CveAggregate> = HashMap::new();
    for asset in assets {
        for v in &asset.vulns {
            let entry = merged.entry(v.cve_id.as_str()).or_insert(CveAggregate {
                severity: Severity::None,
                cvss: None,
                epss: None,
                kev: false,
                affected: 0,
            });
            entry.affected += 1;
            entry.severity = entry.severity.max(v.severity);
            entry.kev |= v.kev;
            if let Some(c) = &v.cvss {
                entry.cvss = Some(entry.cvss.map_or(c.base_score, |x| x.max(c.base_score)));
            }
            if let Some(e) = v.epss {
                entry.epss = Some(entry.epss.map_or(e.score, |x| x.max(e.score)));
            }
        }
    }

    let unique_cves = merged.len();
    let kev_cves = merged.values().filter(|c| c.kev).count();
    let critical_cves = merged
        .values()
        .filter(|c| c.severity == Severity::Critical)
        .count();
    let high_cves = merged
        .values()
        .filter(|c| c.severity == Severity::High)
        .count();
    let assets_with_kev = assets
        .iter()
        .filter(|a| a.vulns.iter().any(|v| v.kev))
        .count();

    let mut ranked: Vec<(&str, CveAggregate)> = merged.into_iter().collect();
    ranked.sort_by(|(id_x, x), (id_y, y)| {
        y.kev
            .cmp(&x.kev)
            .then_with(|| {
                y.epss
                    .unwrap_or(-1.0)
                    .partial_cmp(&x.epss.unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                y.cvss
                    .unwrap_or(-1.0)
                    .partial_cmp(&x.cvss.unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| id_x.cmp(id_y))
    });
    let top_cves = ranked
        .into_iter()
        .take(TOP_LIMIT)
        .map(|(cve_id, c)| TopCve {
            cve_id: cve_id.to_owned(),
            severity: c.severity,
            cvss: c.cvss,
            epss: c.epss,
            kev: c.kev,
            affected: c.affected,
        })
        .collect();

    VulnPosture {
        unique_cves,
        kev_cves,
        critical_cves,
        high_cves,
        assets_with_kev,
        top_cves,
    }
}

fn activity(events: &[EventFacts], cutoff: OffsetDateTime) -> Activity {
    let in_period: Vec<&EventFacts> = events.iter().filter(|e| e.at >= cutoff).collect();
    let count = |kind: &str| in_period.iter().filter(|e| e.kind == kind).count();
    Activity {
        events_in_period: in_period.len(),
        new_assets: count("asset.new"),
        service_changes: count("services.changed"),
        vuln_changes: count("vulns.changed"),
        risk_changes: count("risk.changed"),
    }
}

#[allow(clippy::cast_precision_loss)]
fn monitoring(
    assets: &[AssetFacts],
    monitor: Option<&MonitorFacts>,
    cutoff: OffsetDateTime,
) -> Monitoring {
    let coverage_percent = if assets.is_empty() {
        0.0
    } else {
        let seen = assets.iter().filter(|a| a.last_seen >= cutoff).count();
        (seen as f32 / assets.len() as f32) * 100.0
    };
    Monitoring {
        configured: monitor.is_some(),
        enabled: monitor.is_some_and(|m| m.enabled),
        interval_minutes: monitor.map(|m| m.interval_minutes),
        target: monitor.map(|m| m.target.clone()),
        last_run_at: monitor.and_then(|m| m.last_run_at),
        coverage_percent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{Confidence, Cvss, Epss};

    fn at(days_ago: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(1000 - days_ago)
    }

    fn now() -> OffsetDateTime {
        at(0)
    }

    fn vuln(
        cve: &str,
        severity: Severity,
        cvss: f32,
        epss: Option<f32>,
        kev: bool,
    ) -> Vulnerability {
        Vulnerability {
            cve_id: cve.to_owned(),
            cvss: Some(Cvss {
                base_score: cvss,
                vector: None,
            }),
            epss: epss.map(|score| Epss {
                score,
                percentile: Some(score),
            }),
            kev,
            severity,
            match_confidence: Confidence::High,
        }
    }

    fn asset(name: &str, risk: f32, vulns: Vec<Vulnerability>) -> AssetFacts {
        AssetFacts {
            name: name.to_owned(),
            ip: None,
            asset_type: AssetType::It,
            device_role: DeviceRole::Unknown,
            criticality: Criticality::Medium,
            exposure: Exposure::Internal,
            risk: RiskScore {
                value: risk,
                band: RiskBand::from_value(risk),
                confidence: Confidence::High,
            },
            vulns,
            first_seen: at(40),
            last_seen: at(0),
        }
    }

    #[test]
    fn inventory_breaks_down_by_device_role() {
        let mut dc1 = asset("dc-1", 90.0, vec![]);
        dc1.device_role = DeviceRole::DomainController;
        let mut dc2 = asset("dc-2", 80.0, vec![]);
        dc2.device_role = DeviceRole::DomainController;
        let mut cam = asset("cam-1", 40.0, vec![]);
        cam.device_role = DeviceRole::Camera;
        // One asset left as Unknown role.
        let plain = asset("ws-1", 10.0, vec![]);

        let inv = inventory(&[dc1, dc2, cam, plain], at(30));
        // Largest first: DomainController=2, then Camera=1 and Unknown=1.
        assert_eq!(inv.by_role[0].role, DeviceRole::DomainController);
        assert_eq!(inv.by_role[0].count, 2);
        assert!(inv
            .by_role
            .iter()
            .any(|r| r.role == DeviceRole::Camera && r.count == 1));
        // Zero-count roles are excluded.
        assert!(inv.by_role.iter().all(|r| r.count > 0));
        assert!(inv.by_role.iter().all(|r| r.role != DeviceRole::Nas));
    }

    #[test]
    fn empty_inventory_builds_a_calm_report() {
        let report = build(&[], &[], &[], None, now(), 30);
        assert_eq!(report.inventory.total, 0);
        assert_eq!(report.vulnerabilities.unique_cves, 0);
        assert!((report.risk.average - 0.0).abs() < f32::EPSILON);
        assert!((report.monitoring.coverage_percent - 0.0).abs() < f32::EPSILON);
        // Monitoring inactive is still worth a warning; nothing else.
        assert!(report
            .highlights
            .iter()
            .any(|h| h.level == HighlightLevel::Warn && h.text.contains("monitoring")));
    }

    #[test]
    fn kev_exposure_leads_the_highlights() {
        let assets = vec![
            asset(
                "web-1",
                85.0,
                vec![vuln("CVE-1", Severity::Critical, 9.8, Some(0.9), true)],
            ),
            asset("db-1", 30.0, vec![]),
        ];
        let report = build(&assets, &[], &[], None, now(), 30);
        assert_eq!(report.highlights[0].level, HighlightLevel::Critical);
        assert!(report.highlights[0].text.contains("Known Exploited"));
        assert_eq!(report.vulnerabilities.assets_with_kev, 1);
        assert_eq!(report.vulnerabilities.kev_cves, 1);
    }

    #[test]
    fn new_and_stale_assets_follow_the_period_window() {
        let mut fresh = asset("fresh", 10.0, vec![]);
        fresh.first_seen = at(3); // inside the 30-day window
        let mut gone = asset("gone", 10.0, vec![]);
        gone.first_seen = at(80);
        gone.last_seen = at(45); // not seen within the window
        let report = build(&[fresh, gone], &[], &[], None, now(), 30);
        assert_eq!(report.inventory.new_in_period, 1);
        assert_eq!(report.inventory.stale, 1);
        // Coverage: 1 of 2 seen in the window.
        assert!((report.monitoring.coverage_percent - 50.0).abs() < 0.01);
    }

    #[test]
    fn top_cves_rank_kev_then_epss_then_cvss() {
        let assets = vec![asset(
            "a",
            50.0,
            vec![
                vuln("CVE-CVSS", Severity::Critical, 10.0, None, false),
                vuln("CVE-EPSS", Severity::High, 7.0, Some(0.95), false),
                vuln("CVE-KEV", Severity::Medium, 5.0, Some(0.10), true),
            ],
        )];
        let report = build(&assets, &[], &[], None, now(), 30);
        let order: Vec<&str> = report
            .vulnerabilities
            .top_cves
            .iter()
            .map(|c| c.cve_id.as_str())
            .collect();
        assert_eq!(order, vec!["CVE-KEV", "CVE-EPSS", "CVE-CVSS"]);
    }

    #[test]
    fn cve_aggregation_merges_across_assets() {
        let assets = vec![
            asset(
                "a",
                50.0,
                vec![vuln("CVE-X", Severity::High, 7.0, Some(0.2), false)],
            ),
            asset(
                "b",
                60.0,
                vec![vuln("CVE-X", Severity::Critical, 9.1, Some(0.5), true)],
            ),
        ];
        let report = build(&assets, &[], &[], None, now(), 30);
        assert_eq!(report.vulnerabilities.unique_cves, 1);
        let top = &report.vulnerabilities.top_cves[0];
        assert_eq!(top.affected, 2);
        assert_eq!(top.severity, Severity::Critical);
        assert!(top.kev);
        assert!((top.cvss.unwrap() - 9.1).abs() < 0.01);
        assert!((top.epss.unwrap() - 0.5).abs() < 0.01);
    }

    #[test]
    fn activity_counts_only_events_within_the_period() {
        let events = vec![
            EventFacts {
                kind: "asset.new".to_owned(),
                at: at(5),
            },
            EventFacts {
                kind: "risk.changed".to_owned(),
                at: at(2),
            },
            EventFacts {
                kind: "vulns.changed".to_owned(),
                at: at(60), // outside
            },
        ];
        let report = build(&[], &[], &events, None, now(), 30);
        assert_eq!(report.activity.events_in_period, 2);
        assert_eq!(report.activity.new_assets, 1);
        assert_eq!(report.activity.risk_changes, 1);
        assert_eq!(report.activity.vuln_changes, 0);
    }

    #[test]
    fn distribution_covers_all_bands_worst_first() {
        let report = build(&[asset("a", 85.0, vec![])], &[], &[], None, now(), 30);
        let bands: Vec<RiskBand> = report.risk.distribution.iter().map(|b| b.band).collect();
        assert_eq!(
            bands,
            vec![
                RiskBand::Critical,
                RiskBand::High,
                RiskBand::Medium,
                RiskBand::Low,
                RiskBand::Info
            ]
        );
        assert_eq!(report.risk.distribution[0].count, 1);
    }

    #[test]
    fn monitoring_facts_pass_through() {
        let monitor = MonitorFacts {
            enabled: true,
            interval_minutes: 60,
            target: "192.168.1.0/24".to_owned(),
            last_run_at: Some(at(1)),
        };
        let report = build(&[], &[], &[], Some(&monitor), now(), 30);
        assert!(report.monitoring.configured);
        assert!(report.monitoring.enabled);
        assert_eq!(report.monitoring.interval_minutes, Some(60));
        // Active monitoring -> no monitoring warning.
        assert!(!report
            .highlights
            .iter()
            .any(|h| h.text.contains("monitoring")));
    }
}

/// Wire-contract tripwire.
///
/// The console (`web/src/lib/api.ts`) hand-mirrors these JSON shapes — there is
/// no codegen, so a Rust-side rename would silently break the console. These
/// tests serialise a representative report and lock the field names and enum
/// string values the console reads. Adding a field is fine (backward-compatible
/// for the console); renaming or removing one it depends on fails here, loudly,
/// pointing at the TS that must be updated in lockstep.
#[cfg(test)]
mod contract {
    use super::*;
    use argus_core::{Confidence, Cvss, Epss, Severity, Vulnerability};
    use serde_json::Value;
    use time::OffsetDateTime;

    fn sample_report() -> ExposureReport {
        let now = OffsetDateTime::UNIX_EPOCH;
        let asset = AssetFacts {
            name: "dc-1".to_owned(),
            ip: Some("10.0.0.1".to_owned()),
            asset_type: AssetType::It,
            device_role: DeviceRole::DomainController,
            criticality: Criticality::Critical,
            exposure: Exposure::Internal,
            risk: RiskScore {
                value: 90.0,
                band: RiskBand::Critical,
                confidence: Confidence::High,
            },
            vulns: vec![Vulnerability {
                cve_id: "CVE-X".to_owned(),
                cvss: Some(Cvss::new(9.8, None)),
                epss: Some(Epss::new(0.9, None)),
                kev: true,
                severity: Severity::Critical,
                match_confidence: Confidence::Confirmed,
            }],
            first_seen: now,
            last_seen: now,
        };
        let advisory = AdvisoryFact {
            rule: "tier0-crown-jewel".to_owned(),
            level: AdvisoryUrgency::Critical,
            title: "Tier-0 reachable".to_owned(),
            rationale: "domain-wide blast radius".to_owned(),
            recommendation: "isolate it".to_owned(),
            affected: vec!["dc-1".to_owned()],
        };
        build(&[asset], &[advisory], &[], None, now, 30)
    }

    fn has(v: &Value, key: &str) -> bool {
        v.get(key).is_some()
    }

    #[test]
    fn report_wire_shape_is_stable() {
        let json = serde_json::to_value(sample_report()).expect("serialize");
        for key in [
            "generated_at",
            "period_days",
            "highlights",
            "action_plan",
            "inventory",
            "risk",
            "vulnerabilities",
            "activity",
            "monitoring",
        ] {
            assert!(has(&json, key), "ExposureReport lost wire field `{key}`");
        }
        let inv = &json["inventory"];
        for key in [
            "total",
            "internet_facing",
            "by_type",
            "by_role",
            "by_criticality",
        ] {
            assert!(has(inv, key), "Inventory lost wire field `{key}`");
        }
        // RoleCount shape + DeviceRole serde value (the DC asset drives one row).
        let role0 = &json["inventory"]["by_role"][0];
        assert!(
            has(role0, "role") && has(role0, "count"),
            "RoleCount shape drifted"
        );
        assert_eq!(
            role0["role"], "domain_controller",
            "DeviceRole serde value drifted"
        );
    }

    #[test]
    fn action_item_wire_shape_is_stable() {
        let json = serde_json::to_value(sample_report()).expect("serialize");
        let plan = json["action_plan"].as_array().expect("action_plan array");
        assert!(!plan.is_empty(), "expected a populated action plan");
        for key in [
            "priority",
            "title",
            "action",
            "effort",
            "rationale",
            "affected",
            "source",
        ] {
            assert!(has(&plan[0], key), "ActionItem lost wire field `{key}`");
        }
        // Enum string values the console's Records are keyed by.
        assert!(
            plan.iter()
                .filter_map(|i| i["priority"].as_str())
                .all(|p| matches!(p, "now" | "this_week" | "soon")),
            "ActionPriority serde value drifted"
        );
        assert!(
            plan.iter()
                .filter_map(|i| i["effort"].as_str())
                .all(|e| matches!(e, "quick" | "moderate" | "project")),
            "ActionEffort serde value drifted"
        );
    }
}

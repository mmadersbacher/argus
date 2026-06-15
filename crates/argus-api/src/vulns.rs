//! Aggregated vulnerability view: `GET /api/vulns` collapses every CVE across
//! the tenant's assets into one entry carrying the merged scores and the list
//! of affected assets.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

use argus_core::{AssetId, Confidence, RiskBand, Severity};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use time::OffsetDateTime;

use crate::auth::AuthContext;
use crate::db::FindingStatusRow;
use crate::seed::ScoredAsset;
use crate::{monitor, store_error, AppState};

/// One aggregated CVE across all assets of a tenant.
#[derive(Debug, Serialize)]
pub struct VulnEntry {
    /// CVE identifier (e.g. `CVE-2024-1234`).
    pub cve_id: String,
    /// Highest severity observed across all instances of this CVE.
    pub severity: Severity,
    /// Highest known CVSS base score, if any instance carries one.
    pub cvss: Option<f32>,
    /// Highest known EPSS score (`0.0..=1.0`), if any instance carries one.
    pub epss: Option<f32>,
    /// Whether any instance is on the CISA KEV catalog.
    pub kev: bool,
    /// Best match confidence across all instances — the strongest evidence
    /// that this CVE genuinely applies somewhere in the inventory.
    pub confidence: Confidence,
    /// Assets affected by this CVE, highest risk first.
    pub affected: Vec<AffectedAsset>,
}

/// One affected asset within a [`VulnEntry`].
#[derive(Debug, Serialize)]
pub struct AffectedAsset {
    /// Asset id.
    pub id: AssetId,
    /// Display name, derived like the event feed's `asset_name`
    /// (hostname → IP → shortened asset id).
    pub name: String,
    /// Composite risk score, `0.0..=100.0`.
    pub risk: f32,
    /// Qualitative risk band.
    pub band: RiskBand,
    /// How reliably this CVE was matched to this asset (CPE+version vs.
    /// version-blind).
    pub match_confidence: Confidence,
    /// Analyst triage decision for this (asset, CVE) finding; `None` = open.
    pub finding: Option<FindingState>,
    /// The finding was marked `resolved`, but the asset has been seen by a
    /// scan *after* that decision and still carries the CVE — the fix did
    /// not take (or has regressed) and the triage state is stale.
    pub resolved_but_detected: bool,
}

/// The triage state of one (asset, CVE) finding as embedded in the
/// vulnerability rollup.
#[derive(Debug, Clone, Serialize)]
pub struct FindingState {
    /// `acknowledged`, `resolved` or `false_positive`.
    pub status: String,
    /// Free-text analyst note (may be empty).
    pub note: String,
    /// Who set the status (login email, or `api-key`).
    pub updated_by: String,
    /// When the status was last set.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// `GET /api/vulns` — every CVE across the tenant's inventory, aggregated by
/// CVE id. Readable by every authenticated role.
pub async fn list_vulns(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<VulnEntry>>, (StatusCode, String)> {
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
    let statuses = state
        .store
        .list_finding_statuses(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(aggregate(&assets, &statuses)))
}

/// Collapse per-asset vulnerability lists into one entry per CVE.
///
/// Per CVE: `severity` is the maximum over all instances, `cvss`/`epss` the
/// maximum of the values that are present, and `kev` the OR. `affected` lists
/// each asset carrying the CVE, highest risk first, each with its analyst
/// triage state from `statuses` (absent = open). Entries are sorted KEV
/// first, then by CVSS descending (unknown scores last), then by CVE id
/// descending in numeric `(year, number)` order (ids that do not parse as
/// `CVE-YYYY-NNNNN` sort last, lexicographically).
#[must_use]
pub fn aggregate(assets: &[ScoredAsset], statuses: &[FindingStatusRow]) -> Vec<VulnEntry> {
    let by_finding: HashMap<(uuid::Uuid, &str), &FindingStatusRow> = statuses
        .iter()
        .map(|s| ((s.asset_id, s.cve_id.as_str()), s))
        .collect();
    let mut by_cve: BTreeMap<&str, (VulnEntry, HashSet<AssetId>)> = BTreeMap::new();
    for asset in assets {
        let name = monitor::asset_name(asset);
        for vuln in &asset.vulnerabilities {
            let (entry, seen) = by_cve.entry(vuln.cve_id.as_str()).or_insert_with(|| {
                (
                    VulnEntry {
                        cve_id: vuln.cve_id.clone(),
                        severity: Severity::None,
                        cvss: None,
                        epss: None,
                        kev: false,
                        confidence: Confidence::Low,
                        affected: Vec::new(),
                    },
                    HashSet::new(),
                )
            });
            entry.severity = entry.severity.max(vuln.severity);
            entry.cvss = max_score(entry.cvss, vuln.cvss.as_ref().map(|c| c.base_score));
            entry.epss = max_score(entry.epss, vuln.epss.map(|e| e.score));
            entry.kev |= vuln.kev;
            entry.confidence = entry.confidence.max(vuln.match_confidence);
            // An asset normally lists a CVE once; guard against duplicates so
            // a repeated instance cannot produce a second affected row.
            if seen.insert(asset.asset.id) {
                let finding = by_finding
                    .get(&(asset.asset.id.0, vuln.cve_id.as_str()))
                    .map(|s| FindingState {
                        status: s.status.clone(),
                        note: s.note.clone(),
                        updated_by: s.updated_by.clone(),
                        updated_at: s.updated_at,
                    });
                // "Resolved but still detected": only once a scan has seen
                // the asset *after* the decision — right after triage there
                // is no new evidence yet and the flag would be noise.
                let resolved_but_detected = finding.as_ref().is_some_and(|f| {
                    f.status == "resolved" && asset.asset.last_seen > f.updated_at
                });
                entry.affected.push(AffectedAsset {
                    id: asset.asset.id,
                    name: name.clone(),
                    risk: asset.risk.value,
                    band: asset.risk.band,
                    match_confidence: vuln.match_confidence,
                    finding,
                    resolved_but_detected,
                });
            }
        }
    }

    let mut entries: Vec<VulnEntry> = by_cve.into_values().map(|(entry, _)| entry).collect();
    for entry in &mut entries {
        entry.affected.sort_by(|a, b| b.risk.total_cmp(&a.risk));
    }
    entries.sort_by(|a, b| {
        b.kev
            .cmp(&a.kev)
            .then_with(|| cmp_cvss_desc(a.cvss, b.cvss))
            .then_with(|| cmp_cve_id_desc(&a.cve_id, &b.cve_id))
    });
    entries
}

/// Maximum of two optional scores, ignoring absent values.
fn max_score(a: Option<f32>, b: Option<f32>) -> Option<f32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    }
}

/// Descending CVSS order with unknown (`None`) scores sorted last.
fn cmp_cvss_desc(a: Option<f32>, b: Option<f32>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => y.total_cmp(&x),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Descending CVE-id order: ids parseable as `CVE-YYYY-NNNNN` compare
/// numerically by `(year, number)` so that e.g. `CVE-2024-10000` sorts above
/// `CVE-2024-9999`; ids that do not parse sort after all parseable ones,
/// lexicographically among themselves.
fn cmp_cve_id_desc(a: &str, b: &str) -> Ordering {
    match (parse_cve_id(a), parse_cve_id(b)) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

/// Parse a `CVE-YYYY-NNNNN` id into `(year, number)`; `None` when the id does
/// not match that shape.
fn parse_cve_id(id: &str) -> Option<(u16, u32)> {
    let (year, number) = id.strip_prefix("CVE-")?.split_once('-')?;
    Some((year.parse().ok()?, number.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use argus_core::tenant::Role;
    use argus_core::{
        Asset, AssetType, Confidence, Criticality, Cvss, Epss, Exposure, Fingerprint, Interface,
        RiskScore, Vulnerability,
    };
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::auth::{AuthKeys, LoginLimiter};
    use crate::store::{IngestLocks, Store};

    use super::*;

    fn vuln(
        cve: &str,
        severity: Severity,
        cvss: Option<f32>,
        epss: Option<f32>,
        kev: bool,
    ) -> Vulnerability {
        Vulnerability {
            cve_id: cve.to_owned(),
            cvss: cvss.map(|base_score| Cvss {
                base_score,
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

    fn asset(host: &str, risk_value: f32, vulns: Vec<Vulnerability>) -> ScoredAsset {
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
                value: risk_value,
                band: RiskBand::from_value(risk_value),
                confidence: Confidence::High,
            },
            overrides: crate::seed::AssetOverrides::default(),
        }
    }

    #[test]
    fn aggregate_confidence_is_the_best_across_instances() {
        let mut weak = vuln("CVE-2024-1", Severity::High, Some(8.0), None, false);
        weak.match_confidence = Confidence::Low;
        let mut strong = vuln("CVE-2024-1", Severity::High, Some(8.0), None, false);
        strong.match_confidence = Confidence::Confirmed;
        let entries = aggregate(
            &[asset("a", 40.0, vec![weak]), asset("b", 60.0, vec![strong])],
            &[],
        );
        assert_eq!(entries.len(), 1);
        // Aggregate is the best evidence; per-asset confidence is preserved,
        // highest-risk asset first.
        assert_eq!(entries[0].confidence, Confidence::Confirmed);
        assert_eq!(
            entries[0].affected[0].match_confidence,
            Confidence::Confirmed
        );
        assert_eq!(entries[0].affected[1].match_confidence, Confidence::Low);
    }

    #[test]
    fn shared_cve_is_one_entry_with_score_maxima() {
        let web = asset(
            "web-01",
            88.4,
            vec![vuln(
                "CVE-2024-1234",
                Severity::Medium,
                Some(5.0),
                None,
                false,
            )],
        );
        let db = asset(
            "db-01",
            42.0,
            vec![vuln(
                "CVE-2024-1234",
                Severity::Critical,
                Some(9.8),
                Some(0.97),
                false,
            )],
        );
        let entries = aggregate(&[web, db], &[]);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.cve_id, "CVE-2024-1234");
        assert_eq!(entry.severity, Severity::Critical);
        assert!((entry.cvss.unwrap() - 9.8).abs() < f32::EPSILON);
        assert!((entry.epss.unwrap() - 0.97).abs() < f32::EPSILON);
        assert!(!entry.kev);
        assert_eq!(entry.affected.len(), 2);
    }

    #[test]
    fn sorting_is_kev_first_then_cvss_desc_then_cve_id_desc() {
        let a = asset(
            "host-01",
            10.0,
            vec![
                vuln("CVE-2024-2", Severity::High, Some(9.8), None, false),
                // KEV with the LOWEST cvss must still sort first.
                vuln("CVE-2020-1", Severity::Low, Some(5.0), None, true),
                // Unknown cvss sorts last.
                vuln("CVE-2023-3", Severity::None, None, None, false),
                // Same cvss as CVE-2024-2: tie broken by cve_id descending.
                vuln("CVE-2024-4", Severity::High, Some(9.8), None, false),
            ],
        );
        let entries = aggregate(std::slice::from_ref(&a), &[]);
        let ids: Vec<&str> = entries.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(
            ids,
            ["CVE-2020-1", "CVE-2024-4", "CVE-2024-2", "CVE-2023-3"]
        );
    }

    #[test]
    fn cve_id_tiebreak_is_numeric_not_lexicographic() {
        // Same kev and cvss: lexicographically "CVE-2024-9999" > "CVE-2024-10000",
        // but numerically 10000 > 9999 — the numeric order must win.
        let a = asset(
            "host-01",
            10.0,
            vec![
                vuln("CVE-2024-9999", Severity::High, Some(9.8), None, false),
                vuln("CVE-2024-10000", Severity::High, Some(9.8), None, false),
            ],
        );
        let entries = aggregate(std::slice::from_ref(&a), &[]);
        let ids: Vec<&str> = entries.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, ["CVE-2024-10000", "CVE-2024-9999"]);
    }

    #[test]
    fn unparseable_cve_id_sorts_after_parseable_ones() {
        // "CVE-2024-ABCD" does not parse as (year, number) and must sort
        // behind every parseable id at the same kev/cvss tier.
        let a = asset(
            "host-01",
            10.0,
            vec![
                vuln("CVE-2024-ABCD", Severity::High, Some(9.8), None, false),
                vuln("CVE-2020-1", Severity::High, Some(9.8), None, false),
            ],
        );
        let entries = aggregate(std::slice::from_ref(&a), &[]);
        let ids: Vec<&str> = entries.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, ["CVE-2020-1", "CVE-2024-ABCD"]);
    }

    #[test]
    fn affected_is_sorted_by_risk_descending() {
        let shared = |sev| vec![vuln("CVE-2024-7", sev, Some(7.5), None, false)];
        let low = asset("low-01", 12.0, shared(Severity::High));
        let high = asset("high-01", 91.0, shared(Severity::High));
        let mid = asset("mid-01", 55.5, shared(Severity::High));
        let entries = aggregate(&[low, high, mid], &[]);
        assert_eq!(entries.len(), 1);
        let names: Vec<&str> = entries[0]
            .affected
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["high-01", "mid-01", "low-01"]);
        assert_eq!(entries[0].affected[0].band, RiskBand::Critical);
        assert_eq!(entries[0].affected[2].band, RiskBand::Info);
    }

    fn status_row(
        asset_id: Uuid,
        cve: &str,
        status: &str,
        updated_at: OffsetDateTime,
    ) -> FindingStatusRow {
        FindingStatusRow {
            asset_id,
            cve_id: cve.to_owned(),
            status: status.to_owned(),
            note: String::new(),
            updated_by: "analyst@argus.local".to_owned(),
            updated_at,
        }
    }

    #[test]
    fn resolved_finding_seen_again_by_a_later_scan_is_flagged() {
        let decided_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let mut a = asset(
            "web-01",
            50.0,
            vec![vuln("CVE-2024-1", Severity::High, Some(8.0), None, false)],
        );
        // The asset was re-scanned an hour after the analyst resolved the
        // finding — and the CVE is still in its vuln list.
        a.asset.last_seen = decided_at + time::Duration::hours(1);
        let statuses = vec![status_row(
            a.asset.id.0,
            "CVE-2024-1",
            "resolved",
            decided_at,
        )];
        let entries = aggregate(std::slice::from_ref(&a), &statuses);
        assert!(entries[0].affected[0].resolved_but_detected);
    }

    #[test]
    fn resolved_finding_without_a_newer_scan_is_not_flagged() {
        let mut a = asset(
            "web-01",
            50.0,
            vec![vuln("CVE-2024-1", Severity::High, Some(8.0), None, false)],
        );
        a.asset.last_seen = OffsetDateTime::UNIX_EPOCH;
        // Decision is newer than the last scan: no new evidence yet.
        let decided_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let statuses = vec![status_row(
            a.asset.id.0,
            "CVE-2024-1",
            "resolved",
            decided_at,
        )];
        let entries = aggregate(std::slice::from_ref(&a), &statuses);
        assert!(!entries[0].affected[0].resolved_but_detected);
        assert_eq!(
            entries[0].affected[0]
                .finding
                .as_ref()
                .map(|f| f.status.as_str()),
            Some("resolved")
        );
    }

    #[test]
    fn non_resolved_statuses_are_never_flagged() {
        let decided_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        for status in ["acknowledged", "false_positive"] {
            let mut a = asset(
                "web-01",
                50.0,
                vec![vuln("CVE-2024-1", Severity::High, Some(8.0), None, false)],
            );
            a.asset.last_seen = decided_at + time::Duration::hours(1);
            let statuses = vec![status_row(a.asset.id.0, "CVE-2024-1", status, decided_at)];
            let entries = aggregate(std::slice::from_ref(&a), &statuses);
            assert!(
                !entries[0].affected[0].resolved_but_detected,
                "{status} must not flag"
            );
        }
    }

    #[test]
    fn serializes_to_the_contract_shape() {
        let a = asset(
            "web-01",
            88.4,
            vec![vuln(
                "CVE-2024-1234",
                Severity::Critical,
                Some(9.8),
                Some(0.97),
                true,
            )],
        );
        let id = a.asset.id.to_string();
        let json =
            serde_json::to_value(aggregate(std::slice::from_ref(&a), &[])).expect("serialize");
        assert_eq!(json[0]["cve_id"], "CVE-2024-1234");
        assert_eq!(json[0]["severity"], "critical");
        assert!((json[0]["cvss"].as_f64().unwrap() - 9.8).abs() < 1e-6);
        assert_eq!(json[0]["kev"], true);
        assert_eq!(json[0]["affected"][0]["id"], id);
        assert_eq!(json[0]["affected"][0]["name"], "web-01");
        assert_eq!(json[0]["affected"][0]["band"], "critical");
    }

    #[tokio::test]
    async fn handler_is_tenant_isolated_and_viewer_readable() {
        let store = Store::memory();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        store
            .upsert(
                t1,
                &asset(
                    "web-01",
                    70.0,
                    vec![vuln("CVE-2024-1", Severity::High, Some(8.8), None, false)],
                ),
            )
            .await
            .unwrap();
        store
            .upsert(
                t2,
                &asset(
                    "other-01",
                    99.0,
                    vec![vuln(
                        "CVE-2099-9",
                        Severity::Critical,
                        Some(10.0),
                        None,
                        true,
                    )],
                ),
            )
            .await
            .unwrap();
        let state = AppState {
            store,
            keys: AuthKeys::from_secret(b"test-secret"),
            limiter: Arc::new(LoginLimiter::default()),
            signup_enabled: false,
            scan_allow_private: true,
            ingest_locks: IngestLocks::default(),
            intel: argus_vuln::intel::IntelCache::new(None),
        };
        let auth = AuthContext {
            tenant_id: t1,
            user_id: None,
            email: None,
            role: Role::Viewer,
        };
        let Json(entries) = list_vulns(auth, State(state)).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-1");
        assert_eq!(entries[0].affected[0].name, "web-01");
    }
}

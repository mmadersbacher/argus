//! # argus-vuln
//!
//! Vulnerability correlation for Argus: match an asset's observed services to
//! known CVEs (with real CVSS, EPSS and CISA-KEV signals) and derive the
//! [`RiskInputs`] consumed by the core scoring engine. The bundled [`catalog`]
//! is the curated offline baseline; [`intel::IntelCache`] layers live,
//! CPE-grounded NVD/EPSS/KEV intelligence on top with per-feed caching.

pub mod catalog;
pub mod intel;
pub mod nvd;
pub mod version;

use std::cmp::Ordering;

use argus_core::{
    Confidence, Criticality, Cvss, Epss, Exposure, RiskInputs, Service, Severity, Vulnerability,
};

/// Which versions of a product a CVE affects.
///
/// **Endpoint conventions** — mind these when transcribing an NVD range, since
/// the upper-bound variants disagree on inclusivity:
/// - [`LessThan`](Self::LessThan): exclusive `v < hi` — `hi` is NVD's
///   `versionEndExcluding` (the *first-fixed* version).
/// - [`AtMost`](Self::AtMost): inclusive `v <= hi` — `hi` is the *last-affected*
///   version, no lower bound.
/// - [`Range`](Self::Range): **inclusive both ends** `lo <= v <= hi` — `hi` is
///   the *last-affected* version, **not** NVD's `versionEndExcluding`. Copying a
///   `versionEndExcluding` straight into `hi` over-matches by one release.
/// - [`Branches`](Self::Branches): each interval half-open `[start, fixed)` —
///   `fixed` *is* NVD's `versionEndExcluding` (first-fixed).
/// - [`Exact`](Self::Exact): `v == x`.
#[derive(Debug, Clone, Copy)]
pub enum VersionRange {
    /// All versions (protocol-level CVE, or discovery has no version).
    Any,
    /// Strictly below the given version.
    LessThan(&'static str),
    /// At or below the given version.
    AtMost(&'static str),
    /// Within `[low, high]` inclusive.
    Range(&'static str, &'static str),
    /// Several disjoint affected branches, each a half-open `[start, fixed)`
    /// interval (NVD's `versionStartIncluding`..`versionEndExcluding`). A
    /// version is affected if it falls in ANY interval. This is the honest
    /// shape for multi-branch CVEs, where a single continuous [`Range`] would
    /// also flag the patched per-branch releases that sit between the branches.
    Branches(&'static [(&'static str, &'static str)]),
    /// Exactly this version.
    Exact(&'static str),
}

impl VersionRange {
    /// Whether `version` falls within this range.
    #[must_use]
    pub fn contains(self, version: &str) -> bool {
        match self {
            Self::Any => true,
            Self::LessThan(hi) => version::cmp(version, hi) == Ordering::Less,
            Self::AtMost(hi) => version::cmp(version, hi) != Ordering::Greater,
            Self::Range(lo, hi) => {
                version::cmp(version, lo) != Ordering::Less
                    && version::cmp(version, hi) != Ordering::Greater
            }
            Self::Branches(intervals) => intervals.iter().any(|(start, fixed)| {
                version::cmp(version, start) != Ordering::Less
                    && version::cmp(version, fixed) == Ordering::Less
            }),
            Self::Exact(x) => version::cmp(version, x) == Ordering::Equal,
        }
    }
}

/// A catalogued CVE with the signals needed for risk scoring.
#[derive(Debug, Clone, Copy)]
pub struct CveRecord {
    /// CVE identifier.
    pub cve_id: &'static str,
    /// Product token matched case-insensitively against a service product.
    pub product: &'static str,
    /// Affected version range.
    pub affected: VersionRange,
    /// CVSS base score.
    pub cvss: f32,
    /// EPSS probability, `0.0..=1.0`.
    pub epss: f32,
    /// Whether the CVE is on the CISA Known Exploited Vulnerabilities catalog.
    pub kev: bool,
    /// Qualitative severity.
    pub severity: Severity,
    /// One-line summary.
    pub summary: &'static str,
}

impl CveRecord {
    fn to_vulnerability(self, match_confidence: Confidence) -> Vulnerability {
        Vulnerability {
            cve_id: self.cve_id.to_owned(),
            cvss: Some(Cvss {
                base_score: self.cvss,
                vector: None,
            }),
            // The catalog carries an approximate, frozen EPSS probability and
            // no percentile; the live overlay replaces both when reachable.
            epss: Some(Epss {
                score: self.epss,
                percentile: None,
            }),
            kev: self.kev,
            severity: self.severity,
            match_confidence,
        }
    }
}

/// Extract the first dotted version-looking token from a product string —
/// one that starts with a digit and contains a dot (`8.9p1`, `2.4.49`).
///
/// Requiring a dot avoids mistaking a bare number for a version: a model
/// number or a year ("Windows Server 2019" → not "2019"), which would
/// otherwise be compared against catalog version ranges and mis-correlate.
fn extract_version(product: &str) -> Option<&str> {
    // Also split on '/', so `vendor/version` banners ("Microsoft-IIS/10.0",
    // "Apache/2.4.49") yield the version, not just the "Vendor 1.2.3" form.
    product
        .split(|c: char| c.is_whitespace() || c == '/')
        .find(|tok| tok.starts_with(|c: char| c.is_ascii_digit()) && tok.contains('.'))
}

/// Split a product string into lowercase alphanumeric tokens.
///
/// `"Apache Tomcat 9.0.27 Log4j"` → `["apache", "tomcat", "9", "0", "27", "log4j"]`.
fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Whether a service's tokens contain every word of a catalog product token.
///
/// Word-boundary (whole-token) matching, not raw substring — so `"Praxis"`
/// does not match the `"Axis"` record and `"Offspring"` does not match
/// `"Spring"`, while `"Apache httpd 2.4.49"` still matches `"Apache httpd"`.
fn product_matches(service_tokens: &[String], catalog_product: &str) -> bool {
    let needles = tokenize(catalog_product);
    !needles.is_empty()
        && needles
            .iter()
            .all(|needle| service_tokens.iter().any(|t| t == needle))
}

/// Correlate a single service product string (e.g. `"OpenSSH 8.9p1"`, `"smb"`)
/// against the catalog.
#[must_use]
pub fn correlate_product(product: &str) -> Vec<Vulnerability> {
    let tokens = tokenize(product);
    let version = extract_version(product);
    catalog::CATALOG
        .iter()
        .filter(|rec| product_matches(&tokens, rec.product))
        .filter(|rec| match rec.affected {
            VersionRange::Any => true,
            range => version.is_some_and(|v| range.contains(v)),
        })
        .map(|rec| {
            // A version-blind (`Any`) hit matched only the product token — low
            // confidence. A hit inside an explicit version range was actually
            // version-checked — high confidence.
            let confidence = if matches!(rec.affected, VersionRange::Any) {
                Confidence::Low
            } else {
                Confidence::High
            };
            rec.to_vulnerability(confidence)
        })
        .collect()
}

/// Correlate all of an asset's services, de-duplicated by CVE id.
#[must_use]
pub fn correlate_services(services: &[Service]) -> Vec<Vulnerability> {
    let mut out: Vec<Vulnerability> = Vec::new();
    for service in services {
        let Some(product) = service.product.as_deref() else {
            continue;
        };
        for vuln in correlate_product(product) {
            if !out.iter().any(|existing| existing.cve_id == vuln.cve_id) {
                out.push(vuln);
            }
        }
    }
    out
}

/// Merge a freshly-derived vulnerability into `vulns`, keyed by CVE id, keeping
/// the **strongest** match confidence when the CVE is already present. Without
/// this, a first-seen catalog `Low` would suppress a later NVD `Confirmed` for
/// the same CVE — silently demoting a score-driving finding below the
/// confirmed-only scoring threshold (the exact failure the confidence model
/// exists to prevent).
pub(crate) fn merge_strongest(vulns: &mut Vec<Vulnerability>, candidate: Vulnerability) {
    match vulns.iter_mut().find(|v| v.cve_id == candidate.cve_id) {
        Some(existing) if candidate.match_confidence > existing.match_confidence => {
            // Adopt the higher-confidence match, but never lose curated signals
            // it lacks: an NVD record can arrive `Confirmed` yet carry no
            // CVSS/EPSS and `kev=false` (unscored / awaiting analysis). A
            // wholesale replace would then erase the catalog's curated CVSS/KEV
            // — silently downgrading a flagship KEV Critical on first scan, with
            // no CVSS overlay to restore it. `take()` moves the values out (we
            // overwrite `existing` next, so no clone is needed).
            let mut merged = candidate;
            if merged.cvss.is_none() {
                merged.cvss = existing.cvss.take();
            }
            if merged.epss.is_none() {
                merged.epss = existing.epss.take();
            }
            if !merged.kev {
                merged.kev = existing.kev;
            }
            if merged.severity == Severity::None {
                merged.severity = existing.severity;
            }
            *existing = merged;
        }
        Some(_) => {}
        None => vulns.push(candidate),
    }
}

/// Catalog CVEs whose exploitation strictly requires the legacy SMBv1 dialect.
///
/// When a host is *observed* not to offer SMBv1, these are refuted (an
/// evidence-based negative), not merely left as unverified potentials.
const SMBV1_REQUIRED: &[&str] = &["CVE-2017-0144"]; // EternalBlue

/// Refute SMBv1-only CVEs on a host observed without SMBv1.
///
/// Removes them from `vulns` when `smbv1 == Some(false)`. `None` (not probed)
/// or `Some(true)` leaves them unchanged — only a positive "no SMBv1" refutes.
pub fn refute_smbv1_dependent(vulns: &mut Vec<Vulnerability>, smbv1: Option<bool>) {
    if smbv1 == Some(false) {
        vulns.retain(|v| !SMBV1_REQUIRED.contains(&v.cve_id.as_str()));
    }
}

/// Build [`RiskInputs`] from correlated vulnerabilities plus asset context.
///
/// Only **confirmed** findings drive the score — those whose version
/// applicability was actually verified ([`Vulnerability::is_confirmed`]).
/// Version-blind / CPE-only matches are *potential*: the product is present
/// but applicability is unverified, so they must not inflate the risk (the
/// EternalBlue-on-a-patched-host problem). They are surfaced separately for
/// human verification, not fed into the score.
#[must_use]
pub fn risk_inputs(
    vulns: &[Vulnerability],
    exposure: Exposure,
    criticality: Criticality,
) -> RiskInputs {
    let confirmed = || vulns.iter().filter(|v| v.is_confirmed());
    let max_cvss = confirmed()
        .filter_map(|v| v.cvss.as_ref().map(|c| c.base_score))
        .fold(0.0_f32, f32::max);
    let max_epss = confirmed()
        .filter_map(|v| v.epss.map(|e| e.score))
        .fold(0.0_f32, f32::max);
    let kev_present = confirmed().any(|v| v.kev);
    let critical_vulns = count_severity(confirmed(), Severity::Critical);
    let high_vulns = count_severity(confirmed(), Severity::High);
    // The score's confidence is that of the confirmed finding driving it:
    // highest CVSS, then KEV, then the more certain match. No confirmed
    // findings is a confident "nothing verified".
    let confidence = confirmed()
        .max_by(|a, b| {
            let sa = a.cvss.as_ref().map_or(0.0, |c| c.base_score);
            let sb = b.cvss.as_ref().map_or(0.0, |c| c.base_score);
            sa.partial_cmp(&sb)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.kev.cmp(&b.kev))
                .then_with(|| a.match_confidence.cmp(&b.match_confidence))
        })
        .map_or(Confidence::Confirmed, |v| v.match_confidence);
    RiskInputs {
        max_cvss,
        max_epss,
        kev_present,
        critical_vulns,
        high_vulns,
        exposure,
        criticality,
        confidence,
    }
}

/// Count vulnerabilities at exactly `severity`, saturating at `u32::MAX`
/// (a count no real host approaches).
fn count_severity<'a>(vulns: impl Iterator<Item = &'a Vulnerability>, severity: Severity) -> u32 {
    u32::try_from(vulns.filter(|v| v.severity == severity).count()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_vuln(id: &str, conf: Confidence) -> Vulnerability {
        Vulnerability {
            cve_id: id.to_owned(),
            cvss: Some(Cvss {
                base_score: 9.0,
                vector: None,
            }),
            epss: Some(Epss {
                score: 0.5,
                percentile: None,
            }),
            kev: false,
            severity: Severity::High,
            match_confidence: conf,
        }
    }

    #[test]
    fn merge_strongest_keeps_higher_confidence_regardless_of_order() {
        // catalog Low already present, NVD Confirmed arrives -> Confirmed wins.
        let mut a = vec![mk_vuln("CVE-X", Confidence::Low)];
        merge_strongest(&mut a, mk_vuln("CVE-X", Confidence::Confirmed));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].match_confidence, Confidence::Confirmed);
        // stronger already present, weaker arrives -> unchanged.
        let mut b = vec![mk_vuln("CVE-X", Confidence::Confirmed)];
        merge_strongest(&mut b, mk_vuln("CVE-X", Confidence::Low));
        assert_eq!(b[0].match_confidence, Confidence::Confirmed);
        // different id -> appended.
        let mut c = vec![mk_vuln("CVE-X", Confidence::Medium)];
        merge_strongest(&mut c, mk_vuln("CVE-Y", Confidence::Low));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn merge_strongest_carries_forward_signals_the_candidate_lacks() {
        // Curated catalog entry (kev + cvss + severity) already present; a
        // higher-confidence NVD match arrives bare (no cvss/epss, kev=false).
        // Confidence upgrades, but the curated signals must survive — otherwise
        // a flagship KEV Critical silently loses its score-driving cvss/kev.
        let curated = Vulnerability {
            cve_id: "CVE-2024-6387".into(),
            cvss: Some(Cvss {
                base_score: 8.1,
                vector: None,
            }),
            epss: Some(Epss {
                score: 0.4,
                percentile: None,
            }),
            kev: true,
            severity: Severity::High,
            match_confidence: Confidence::High,
        };
        let bare_nvd = Vulnerability {
            cve_id: "CVE-2024-6387".into(),
            cvss: None,
            epss: None,
            kev: false,
            severity: Severity::None,
            match_confidence: Confidence::Confirmed,
        };
        let mut v = vec![curated];
        merge_strongest(&mut v, bare_nvd);
        assert_eq!(v.len(), 1);
        assert_eq!(
            v[0].match_confidence,
            Confidence::Confirmed,
            "confidence upgraded"
        );
        assert_eq!(
            v[0].cvss.as_ref().map(|c| c.base_score),
            Some(8.1),
            "curated CVSS preserved"
        );
        assert!(v[0].kev, "curated KEV preserved");
        assert_eq!(v[0].severity, Severity::High, "curated severity preserved");
        assert!(v[0].epss.is_some(), "curated EPSS preserved");
    }

    #[test]
    fn version_range_endpoint_conventions_are_pinned() {
        // Range is inclusive-inclusive: both bounds in, one past `hi` out.
        let r = VersionRange::Range("2.4.0", "2.4.55");
        assert!(r.contains("2.4.0"));
        assert!(r.contains("2.4.55"));
        assert!(!r.contains("2.4.56"));
        assert!(!r.contains("2.3.99"));
        // AtMost: inclusive upper bound.
        let a = VersionRange::AtMost("2018.76");
        assert!(a.contains("2018.76"));
        assert!(!a.contains("2018.77"));
        // LessThan: exclusive upper bound.
        let l = VersionRange::LessThan("9.3");
        assert!(!l.contains("9.3"));
        assert!(l.contains("9.2"));
        // Exact: only itself.
        let e = VersionRange::Exact("1.2.3");
        assert!(e.contains("1.2.3"));
        assert!(!e.contains("1.2.4"));
    }

    #[test]
    fn apache_mod_proxy_cves_do_not_match_pre_2_4_versions() {
        // CVE-2021-40438 / CVE-2023-25690 affect the 2.4 branch only. An
        // unbounded AtMost falsely flagged httpd 1.3/2.0/2.2 as High Critical.
        let v = correlate_product("Apache httpd 1.3.41");
        assert!(!v.iter().any(|x| x.cve_id == "CVE-2021-40438"));
        assert!(!v.iter().any(|x| x.cve_id == "CVE-2023-25690"));
    }

    #[test]
    fn apache_mod_proxy_cves_still_match_in_branch_versions() {
        let v = correlate_product("Apache httpd 2.4.40");
        assert!(v.iter().any(|x| x.cve_id == "CVE-2021-40438"));
        assert!(v.iter().any(|x| x.cve_id == "CVE-2023-25690"));
    }

    #[test]
    fn jenkins_cli_cve_does_not_match_1x() {
        assert!(!correlate_product("Jenkins 1.650")
            .iter()
            .any(|x| x.cve_id == "CVE-2024-23897"));
        assert!(correlate_product("Jenkins 2.400")
            .iter()
            .any(|x| x.cve_id == "CVE-2024-23897"));
    }

    #[test]
    fn proftpd_mod_copy_does_not_match_pre_1_3() {
        // mod_copy did not exist before ProFTPD 1.3; AtMost over-matched 1.2.x.
        assert!(!correlate_product("ProFTPD 1.2.10")
            .iter()
            .any(|x| x.cve_id == "CVE-2019-12815"));
        assert!(correlate_product("ProFTPD 1.3.5a")
            .iter()
            .any(|x| x.cve_id == "CVE-2019-12815"));
    }

    #[test]
    fn dropbear_user_enum_matches_all_prior_versions() {
        // AtMost is correct here: every version up to 2018.76 is affected, so a
        // lower bound would wrongly exclude genuinely-affected old releases.
        assert!(correlate_product("dropbear 2016.74")
            .iter()
            .any(|x| x.cve_id == "CVE-2018-15599"));
    }

    #[test]
    fn extract_version_handles_slash_delimited_banner() {
        assert_eq!(extract_version("Microsoft-IIS/10.0"), Some("10.0"));
        assert_eq!(extract_version("Apache/2.4.49"), Some("2.4.49"));
        // Space-delimited and dot-less cases unchanged:
        assert_eq!(extract_version("OpenSSH 8.9p1"), Some("8.9p1"));
        assert_eq!(extract_version("Windows Server 2019"), None);
    }

    #[test]
    fn iis_cve_matches_slash_banner_in_range() {
        // CVE-2015-1635 affects IIS 7.5-8.5. A real "Microsoft-IIS/8.0" banner
        // must correlate; "Microsoft-IIS/10.0" (out of range) must not.
        assert!(correlate_product("Microsoft-IIS/8.0")
            .iter()
            .any(|x| x.cve_id == "CVE-2015-1635"));
        assert!(!correlate_product("Microsoft-IIS/10.0")
            .iter()
            .any(|x| x.cve_id == "CVE-2015-1635"));
    }

    #[test]
    fn openssh_in_range_matches_regresshion() {
        assert!(correlate_product("OpenSSH 8.9p1")
            .iter()
            .any(|v| v.cve_id == "CVE-2024-6387"));
    }

    #[test]
    fn openssh_out_of_range_no_match() {
        assert!(!correlate_product("OpenSSH 9.9")
            .iter()
            .any(|v| v.cve_id == "CVE-2024-6387"));
    }

    #[test]
    fn protocol_level_cves_match_without_version() {
        assert!(correlate_product("smb")
            .iter()
            .any(|v| v.cve_id == "CVE-2017-0144"));
        assert!(correlate_product("rdp")
            .iter()
            .any(|v| v.cve_id == "CVE-2019-0708"));
    }

    #[test]
    fn smb_correlates_both_eternalblue_and_smbghost() {
        let vulns = correlate_product("smb");
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2017-0144"));
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2020-0796"));
    }

    #[test]
    fn versioned_products_match_in_range_only() {
        // Exim 4.89 is inside the Return-of-WIZard range; 4.95 is not.
        assert!(correlate_product("Exim 4.89")
            .iter()
            .any(|v| v.cve_id == "CVE-2019-10149"));
        assert!(!correlate_product("Exim 4.95")
            .iter()
            .any(|v| v.cve_id == "CVE-2019-10149"));
        // Tomcat Ghostcat is version-bounded.
        assert!(correlate_product("Apache Tomcat 9.0.27")
            .iter()
            .any(|v| v.cve_id == "CVE-2020-1938"));
    }

    #[test]
    fn protocol_token_products_correlate() {
        for (product, cve) in [
            ("redis", "CVE-2022-0543"),
            ("Citrix NetScaler Gateway", "CVE-2023-4966"),
            ("Fortinet FortiOS 7.2.1", "CVE-2022-40684"),
            ("Apache Tomcat 9.0.27 Log4j", "CVE-2021-44228"),
        ] {
            assert!(
                correlate_product(product).iter().any(|v| v.cve_id == cve),
                "{product} should correlate {cve}"
            );
        }
    }

    #[test]
    fn heartbleed_range_excludes_the_patched_release() {
        // OpenSSL 1.0.1 .. 1.0.1f is vulnerable; 1.0.1g is the fix.
        assert!(correlate_product("OpenSSL 1.0.1f")
            .iter()
            .any(|v| v.cve_id == "CVE-2014-0160"));
        assert!(correlate_product("OpenSSL 1.0.1g")
            .iter()
            .all(|v| v.cve_id != "CVE-2014-0160"));
    }

    #[test]
    fn bare_year_is_not_mistaken_for_a_version() {
        // "Windows Server 2019" must not yield "2019" as a version (no dot).
        assert_eq!(extract_version("Windows Server 2019"), None);
        // Real dotted versions are still found.
        assert_eq!(extract_version("OpenSSH 8.9p1"), Some("8.9p1"));
        assert_eq!(extract_version("nginx 1.24.0 (Ubuntu)"), Some("1.24.0"));
    }

    #[test]
    fn word_boundary_match_avoids_substring_false_positives() {
        // "Praxis" must not match the "Axis" record; "Offspring" must not match
        // "Spring"; an unrelated banner must not pick up "php"/"xz" by substring.
        assert!(correlate_product("Praxis EMR 2.0")
            .iter()
            .all(|v| v.cve_id != "CVE-2018-10661"));
        assert!(correlate_product("Offspring Media Server 1.0")
            .iter()
            .all(|v| v.cve_id != "CVE-2022-22965"));
        assert!(correlate_product("Pxz Appliance").is_empty());
    }

    #[test]
    fn tomcat_log4j_banner_matches_exactly_its_two_cves() {
        let vulns = correlate_product("Apache Tomcat 9.0.27 Log4j");
        let has = |id: &str| vulns.iter().any(|v| v.cve_id == id);
        assert!(has("CVE-2020-1938")); // Ghostcat (Tomcat range)
        assert!(has("CVE-2021-44228")); // Log4Shell
                                        // Must NOT pick up the "Apache httpd" record (no "httpd" token).
        assert!(!has("CVE-2021-41773"));
    }

    #[test]
    fn risk_inputs_take_worst_signals() {
        let vulns = vec![
            Vulnerability {
                cve_id: "A".into(),
                cvss: Some(Cvss {
                    base_score: 5.0,
                    vector: None,
                }),
                epss: Some(Epss {
                    score: 0.10,
                    percentile: Some(0.10),
                }),
                kev: false,
                severity: Severity::Medium,
                match_confidence: Confidence::High,
            },
            Vulnerability {
                cve_id: "B".into(),
                cvss: Some(Cvss {
                    base_score: 9.8,
                    vector: None,
                }),
                epss: Some(Epss {
                    score: 0.90,
                    percentile: Some(0.90),
                }),
                kev: true,
                severity: Severity::Critical,
                match_confidence: Confidence::Confirmed,
            },
        ];
        let inputs = risk_inputs(&vulns, Exposure::InternetFacing, Criticality::High);
        assert!((inputs.max_cvss - 9.8).abs() < f32::EPSILON);
        assert!((inputs.max_epss - 0.90).abs() < f32::EPSILON);
        assert!(inputs.kev_present);
        // One Critical (B) and one Medium (A) → the surface counts reflect
        // severity, not just the worst signal.
        assert_eq!(inputs.critical_vulns, 1);
        assert_eq!(inputs.high_vulns, 0);
    }

    #[test]
    fn risk_inputs_count_findings_by_severity() {
        let mk = |cve: &str, sev| Vulnerability {
            cve_id: cve.into(),
            cvss: None,
            epss: None,
            kev: false,
            severity: sev,
            match_confidence: Confidence::High,
        };
        let vulns = vec![
            mk("A", Severity::Critical),
            mk("B", Severity::Critical),
            mk("C", Severity::High),
            mk("D", Severity::Medium),
            mk("E", Severity::Low),
        ];
        let inputs = risk_inputs(&vulns, Exposure::Internal, Criticality::Medium);
        assert_eq!(inputs.critical_vulns, 2);
        assert_eq!(inputs.high_vulns, 1);
    }

    #[test]
    fn version_blind_matches_are_low_confidence() {
        // A protocol-level (`VersionRange::Any`) catalog hit is version-blind.
        let smb = correlate_product("smb");
        assert!(!smb.is_empty());
        assert!(smb.iter().all(|v| v.match_confidence == Confidence::Low));
        // A version-checked hit (OpenSSH inside the regreSSHion range) is High.
        let ssh = correlate_product("OpenSSH 8.9p1");
        let regresshion = ssh
            .iter()
            .find(|v| v.cve_id == "CVE-2024-6387")
            .expect("regreSSHion correlates");
        assert_eq!(regresshion.match_confidence, Confidence::High);
    }

    #[test]
    fn version_blind_findings_do_not_drive_the_score() {
        // The EternalBlue-on-a-patched-host fix: a high-CVSS but version-blind
        // (potential) finding must NOT inflate the score — only the confirmed,
        // version-checked finding counts.
        let vulns = vec![
            Vulnerability {
                cve_id: "confirmed-medium".into(),
                cvss: Some(Cvss {
                    base_score: 4.0,
                    vector: None,
                }),
                epss: None,
                kev: false,
                severity: Severity::Medium,
                match_confidence: Confidence::Confirmed,
            },
            Vulnerability {
                cve_id: "potential-critical".into(),
                cvss: Some(Cvss {
                    base_score: 9.8,
                    vector: None,
                }),
                epss: Some(Epss {
                    score: 0.9,
                    percentile: None,
                }),
                kev: true,
                severity: Severity::Critical,
                match_confidence: Confidence::Low,
            },
        ];
        let inputs = risk_inputs(&vulns, Exposure::Internal, Criticality::Medium);
        assert!(
            (inputs.max_cvss - 4.0).abs() < f32::EPSILON,
            "a version-blind 9.8 must not drive max_cvss"
        );
        assert!(
            !inputs.kev_present,
            "a version-blind KEV must not set kev_present"
        );
        assert_eq!(
            inputs.critical_vulns, 0,
            "the version-blind Critical must not be counted"
        );
        assert_eq!(inputs.confidence, Confidence::Confirmed);
    }

    #[test]
    fn an_all_potential_asset_yields_no_score_driving_findings() {
        // `smb` → EternalBlue + SMBGhost are version-blind (potential). An SMB
        // host with no confirmed findings produces zero score inputs (Info),
        // not a KEV-inflated Medium.
        let smb = correlate_product("smb");
        assert!(!smb.is_empty());
        assert!(
            smb.iter().all(Vulnerability::is_potential),
            "all smb catalog hits are version-blind potentials"
        );
        let inputs = risk_inputs(&smb, Exposure::Internal, Criticality::Medium);
        assert!((inputs.max_cvss - 0.0).abs() < f32::EPSILON);
        assert!(!inputs.kev_present);
        assert_eq!(inputs.critical_vulns, 0);
    }

    #[test]
    fn smbv1_refutation_drops_eternalblue_only_when_observed_off() {
        let has_eb = |v: &[Vulnerability]| v.iter().any(|x| x.cve_id == "CVE-2017-0144");

        // SMBv1 observed OFF → EternalBlue refuted (removed entirely).
        let mut off = correlate_product("smb");
        refute_smbv1_dependent(&mut off, Some(false));
        assert!(!has_eb(&off), "SMBv1 off must refute EternalBlue");
        // SMBGhost needs SMBv3, not SMBv1 — absent SMBv1 must not refute it.
        assert!(off.iter().any(|v| v.cve_id == "CVE-2020-0796"));

        // SMBv1 ON → kept.
        let mut on = correlate_product("smb");
        refute_smbv1_dependent(&mut on, Some(true));
        assert!(has_eb(&on), "SMBv1 on must keep EternalBlue");

        // Not probed (None) → kept as a potential, never refuted on no evidence.
        let mut unknown = correlate_product("smb");
        refute_smbv1_dependent(&mut unknown, None);
        assert!(
            has_eb(&unknown),
            "unprobed must keep EternalBlue as potential"
        );
    }

    #[test]
    fn branches_match_each_interval_and_suppress_the_patched_gaps() {
        // A multi-branch CVE: affected inside any [start, fixed) interval, but
        // the patched per-branch releases between intervals are NOT affected.
        let mariadb = VersionRange::Branches(&[("10.3.0", "10.3.28"), ("10.4.0", "10.4.18")]);
        assert!(mariadb.contains("10.3.27"), "last affected of a branch");
        assert!(!mariadb.contains("10.3.28"), "first fixed of a branch");
        assert!(!mariadb.contains("10.4.30"), "patched, above the 10.4 fix");
        assert!(!mariadb.contains("10.5.1"), "branch not listed at all");
        assert!(mariadb.contains("10.4.0"), "branch base is included");
    }

    #[test]
    fn multi_branch_catalog_fix_removes_the_high_confidence_false_positive() {
        let reports = |s: &str| {
            correlate_product(s)
                .into_iter()
                .find(|v| v.cve_id == "CVE-2021-27928")
        };
        // The defect that drove the fix: a patched intermediate release used to
        // fall inside the single continuous range and report at High. Now it is
        // suppressed, while a genuinely affected version still reports High.
        assert!(
            reports("MariaDB 10.3.28").is_none(),
            "patched -> no High FP"
        );
        assert_eq!(
            reports("MariaDB 10.3.27").map(|v| v.match_confidence),
            Some(Confidence::High),
            "genuinely affected -> still reported, High",
        );
    }
}

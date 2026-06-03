//! # argus-vuln
//!
//! Vulnerability correlation for Argus: match an asset's observed services to
//! known CVEs (with real CVSS, EPSS and CISA-KEV signals) and derive the
//! [`RiskInputs`] consumed by the core scoring engine. The bundled [`catalog`]
//! is a curated seed set — the path to the full NVD/EPSS/KEV feeds is a drop-in
//! `CveRecord` source away.

pub mod catalog;
pub mod nvd;
pub mod version;

use std::cmp::Ordering;

use argus_core::{Criticality, Cvss, Epss, Exposure, RiskInputs, Service, Severity, Vulnerability};

/// Which versions of a product a CVE affects.
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
    fn to_vulnerability(self) -> Vulnerability {
        Vulnerability {
            cve_id: self.cve_id.to_owned(),
            cvss: Some(Cvss {
                base_score: self.cvss,
                vector: None,
            }),
            epss: Some(Epss {
                score: self.epss,
                percentile: self.epss,
            }),
            kev: self.kev,
            severity: self.severity,
        }
    }
}

/// Extract the first version-looking token (starts with a digit) from a product string.
fn extract_version(product: &str) -> Option<&str> {
    product
        .split_whitespace()
        .find(|tok| tok.chars().next().is_some_and(|c| c.is_ascii_digit()))
}

/// Correlate a single service product string (e.g. `"OpenSSH 8.9p1"`, `"smb"`)
/// against the catalog.
#[must_use]
pub fn correlate_product(product: &str) -> Vec<Vulnerability> {
    let lower = product.to_lowercase();
    let version = extract_version(product);
    catalog::CATALOG
        .iter()
        .filter(|rec| lower.contains(&rec.product.to_lowercase()))
        .filter(|rec| match rec.affected {
            VersionRange::Any => true,
            range => version.is_some_and(|v| range.contains(v)),
        })
        .map(|rec| rec.to_vulnerability())
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

/// Build [`RiskInputs`] from correlated vulnerabilities plus asset context.
#[must_use]
pub fn risk_inputs(
    vulns: &[Vulnerability],
    exposure: Exposure,
    criticality: Criticality,
) -> RiskInputs {
    let max_cvss = vulns
        .iter()
        .filter_map(|v| v.cvss.as_ref().map(|c| c.base_score))
        .fold(0.0_f32, f32::max);
    let max_epss = vulns
        .iter()
        .filter_map(|v| v.epss.map(|e| e.score))
        .fold(0.0_f32, f32::max);
    let kev_present = vulns.iter().any(|v| v.kev);
    RiskInputs {
        max_cvss,
        max_epss,
        kev_present,
        exposure,
        criticality,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    percentile: 0.10,
                }),
                kev: false,
                severity: Severity::Medium,
            },
            Vulnerability {
                cve_id: "B".into(),
                cvss: Some(Cvss {
                    base_score: 9.8,
                    vector: None,
                }),
                epss: Some(Epss {
                    score: 0.90,
                    percentile: 0.90,
                }),
                kev: true,
                severity: Severity::Critical,
            },
        ];
        let inputs = risk_inputs(&vulns, Exposure::InternetFacing, Criticality::High);
        assert!((inputs.max_cvss - 9.8).abs() < f32::EPSILON);
        assert!((inputs.max_epss - 0.90).abs() < f32::EPSILON);
        assert!(inputs.kev_present);
    }
}

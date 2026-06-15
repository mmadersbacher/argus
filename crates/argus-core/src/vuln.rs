//! Vulnerability data: CVEs with CVSS, EPSS, and CISA KEV context.

use serde::{Deserialize, Serialize};

/// Qualitative severity, ordered `None < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No meaningful severity.
    #[default]
    None,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl Severity {
    /// Derive a qualitative severity from a CVSS base score using the standard
    /// CVSS v3.1 severity bands.
    #[must_use]
    pub fn from_cvss(score: f32) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::None
        }
    }
}

/// Confidence in an observation or correlation, ordered
/// `Low < Medium < High < Confirmed`.
///
/// For a [`Vulnerability`] this expresses *how* the CVE was matched to the
/// asset, so a high risk score backed only by weak matches is visibly less
/// certain:
/// - `Confirmed` — live NVD, precise CPE identity, observed version matched
///   against NVD's published version range,
/// - `High` — catalog match with the observed version inside an explicit
///   version range,
/// - `Medium` — precise CPE identity but no version was checked,
/// - `Low` — version-blind (a product-token or all-versions match, e.g. a
///   protocol-level CVE that applies regardless of version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Weak / version-blind signal.
    Low,
    /// Moderate signal (the neutral default for untracked data).
    #[default]
    Medium,
    /// Strong signal.
    High,
    /// Verified / confirmed.
    Confirmed,
}

/// CVSS base score and (optional) vector string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cvss {
    /// Base score, `0.0..=10.0`.
    pub base_score: f32,
    /// CVSS vector string, if available.
    pub vector: Option<String>,
}

/// EPSS (Exploit Prediction Scoring System) data point.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Epss {
    /// Probability of exploitation in the next 30 days, `0.0..=1.0`.
    pub score: f32,
    /// Percentile rank among all scored CVEs, `0.0..=1.0`, when known. `None`
    /// for offline-catalog entries, which carry an approximate score but no
    /// percentile.
    pub percentile: Option<f32>,
}

/// A vulnerability affecting one or more assets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE identifier (e.g. `CVE-2024-3094`).
    pub cve_id: String,
    /// CVSS scoring, if known.
    pub cvss: Option<Cvss>,
    /// EPSS data, if known.
    pub epss: Option<Epss>,
    /// Whether the CVE is on the CISA Known Exploited Vulnerabilities catalog.
    pub kev: bool,
    /// Qualitative severity.
    pub severity: Severity,
    /// How reliably this CVE was matched to the asset (CPE + version vs.
    /// version-blind). Aggregated into the asset's [`crate::RiskScore`]
    /// confidence. Defaults to [`Confidence::Medium`] for data persisted
    /// before match-confidence tracking existed.
    #[serde(default)]
    pub match_confidence: Confidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_bands_map_correctly() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(3.1), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::None);
    }

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Critical > Severity::Medium);
    }

    #[test]
    fn vulnerability_roundtrips_json() {
        let v = Vulnerability {
            cve_id: "CVE-2024-3094".into(),
            cvss: Some(Cvss {
                base_score: 10.0,
                vector: None,
            }),
            epss: Some(Epss {
                score: 0.94,
                percentile: Some(0.99),
            }),
            kev: true,
            severity: Severity::Critical,
            match_confidence: Confidence::Confirmed,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: Vulnerability = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

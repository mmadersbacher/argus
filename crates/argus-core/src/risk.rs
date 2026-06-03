//! Composite exposure / risk scoring.
//!
//! Blends vulnerability severity (CVSS), exploit likelihood (EPSS + CISA KEV),
//! network exposure and business criticality into a single `0..=100` score —
//! the approach used by tools like CVE_Prioritizer, adapted to asset context.

use serde::{Deserialize, Serialize};

use crate::asset::{Criticality, Exposure};

/// Qualitative risk band derived from a [`RiskScore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskBand {
    /// Informational (`0..20`).
    Info,
    /// Low (`20..40`).
    Low,
    /// Medium (`40..60`).
    Medium,
    /// High (`60..80`).
    High,
    /// Critical (`80..=100`).
    Critical,
}

impl RiskBand {
    /// Map a numeric `0..=100` score onto a band.
    #[must_use]
    pub fn from_value(value: f32) -> Self {
        if value >= 80.0 {
            Self::Critical
        } else if value >= 60.0 {
            Self::High
        } else if value >= 40.0 {
            Self::Medium
        } else if value >= 20.0 {
            Self::Low
        } else {
            Self::Info
        }
    }
}

/// Inputs to the risk computation for a single asset.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskInputs {
    /// Highest CVSS base score among the asset's vulnerabilities, `0.0..=10.0`.
    pub max_cvss: f32,
    /// Highest EPSS probability among the asset's vulnerabilities, `0.0..=1.0`.
    pub max_epss: f32,
    /// Whether any of the asset's vulnerabilities is on the CISA KEV catalog.
    pub kev_present: bool,
    /// Network exposure of the asset.
    pub exposure: Exposure,
    /// Business criticality of the asset.
    pub criticality: Criticality,
}

/// A computed risk score with its qualitative band.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// Numeric score, `0.0..=100.0`.
    pub value: f32,
    /// Qualitative band.
    pub band: RiskBand,
}

impl RiskScore {
    /// Compute the composite risk score from [`RiskInputs`].
    ///
    /// `severity` (normalised CVSS) is weighted 60%, `likelihood` 40%. CISA KEV
    /// membership is empirical proof of exploitation, so it floors likelihood
    /// high regardless of EPSS. The result is scaled by exposure and business
    /// criticality factors.
    #[must_use]
    pub fn compute(input: &RiskInputs) -> Self {
        let severity = (input.max_cvss / 10.0).clamp(0.0, 1.0);
        let epss = input.max_epss.clamp(0.0, 1.0);
        let likelihood = if input.kev_present {
            epss.max(0.9)
        } else {
            epss
        };

        let exposure_factor = match input.exposure {
            Exposure::InternetFacing => 1.0,
            Exposure::Unknown => 0.85,
            Exposure::Internal => 0.7,
        };
        let criticality_factor = match input.criticality {
            Criticality::Critical => 1.0,
            Criticality::High => 0.9,
            Criticality::Medium => 0.75,
            Criticality::Low => 0.6,
        };

        let base = severity.mul_add(0.6, likelihood * 0.4);
        let value = (base * exposure_factor * criticality_factor * 100.0).clamp(0.0, 100.0);

        Self {
            value,
            band: RiskBand::from_value(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_case_is_critical() {
        let s = RiskScore::compute(&RiskInputs {
            max_cvss: 10.0,
            max_epss: 1.0,
            kev_present: true,
            exposure: Exposure::InternetFacing,
            criticality: Criticality::Critical,
        });
        assert!((s.value - 100.0).abs() < f32::EPSILON);
        assert_eq!(s.band, RiskBand::Critical);
    }

    #[test]
    fn benign_case_is_info() {
        let s = RiskScore::compute(&RiskInputs {
            max_cvss: 0.0,
            max_epss: 0.0,
            kev_present: false,
            exposure: Exposure::Internal,
            criticality: Criticality::Low,
        });
        assert!(s.value < f32::EPSILON);
        assert_eq!(s.band, RiskBand::Info);
    }

    #[test]
    fn kev_raises_likelihood_floor() {
        let base = RiskInputs {
            max_cvss: 5.0,
            max_epss: 0.01,
            kev_present: false,
            exposure: Exposure::Internal,
            criticality: Criticality::Medium,
        };
        let with_kev = RiskInputs {
            kev_present: true,
            ..base
        };
        assert!(RiskScore::compute(&with_kev).value > RiskScore::compute(&base).value);
    }
}

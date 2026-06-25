//! Composite exposure / risk scoring.
//!
//! Blends vulnerability severity (CVSS), exploit likelihood (EPSS + CISA KEV),
//! network exposure and business criticality into a single `0..=100` score —
//! the approach used by tools like CVE_Prioritizer, adapted to asset context.

use serde::{Deserialize, Serialize};

use crate::asset::{Criticality, Exposure};
use crate::vuln::Confidence;

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
    /// Every band, in declaration order (`Info`..`Critical`). Single source of
    /// truth for callers that enumerate all bands (risk distributions); kept
    /// exhaustive by the `all_bands` test.
    pub const ALL: [Self; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// Map a numeric `0..=100` score onto a band. A non-finite `value` (which
    /// `compute` never produces, but a direct caller could pass) maps to
    /// [`RiskBand::Info`], since every `>=` comparison against `NaN` is false.
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
    /// Count of Critical-severity (CVSS ≥ 9.0) vulnerabilities on the asset.
    /// Feeds the attack-surface uplift so a heavily-vulnerable host outscores
    /// one with a single equivalent finding.
    #[serde(default)]
    pub critical_vulns: u32,
    /// Count of High-severity (7.0 ≤ CVSS < 9.0) vulnerabilities on the asset.
    #[serde(default)]
    pub high_vulns: u32,
    /// Network exposure of the asset.
    pub exposure: Exposure,
    /// Business criticality of the asset.
    pub criticality: Criticality,
    /// Match confidence of the worst (score-driving) vulnerability, carried
    /// into the [`RiskScore`] so a high score backed only by version-blind
    /// matches reads as less certain. Defaults to [`Confidence::Medium`].
    #[serde(default)]
    pub confidence: Confidence,
}

/// A computed risk score with its qualitative band.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// Numeric score, `0.0..=100.0`.
    pub value: f32,
    /// Qualitative band.
    pub band: RiskBand,
    /// Confidence in the score, inherited from the match confidence of the
    /// highest-CVSS vulnerability that drives it. Defaults to
    /// [`Confidence::Medium`] for scores persisted before this existed.
    #[serde(default)]
    pub confidence: Confidence,
}

/// Maximum attack-surface uplift on the base severity/likelihood blend: a
/// host riddled with serious findings scores up to 30 % higher than one with
/// a single equivalent finding. Bounded so volume modulates the worst-case
/// severity rather than overwhelming it.
const SURFACE_MAX_UPLIFT: f32 = 0.30;
/// Saturation scale (in weighted serious findings *beyond the worst*) at
/// which the uplift reaches ~63 % of its maximum, then flattens — so the 2nd
/// serious CVE moves the score far more than the 20th.
const SURFACE_SCALE: f32 = 8.0;

impl RiskScore {
    /// Compute the composite risk score from [`RiskInputs`].
    ///
    /// `severity` (normalised CVSS) is weighted 60%, `likelihood` 40%. CISA KEV
    /// membership is empirical proof of exploitation, so it floors likelihood
    /// high regardless of EPSS. That worst-case blend is then lifted by an
    /// attack-surface factor (how many *serious* findings the host carries,
    /// not just the single worst) and scaled by exposure and business
    /// criticality factors.
    #[must_use]
    pub fn compute(input: &RiskInputs) -> Self {
        // `f32::clamp` propagates NaN, so a non-finite CVSS/EPSS (a malformed
        // feed value) would poison the whole computation into a NaN score that
        // `RiskBand::from_value` then silently bands as `Info`. Map non-finite
        // inputs to 0.0 explicitly so the score stays finite and trustworthy.
        let severity = sanitize_unit(input.max_cvss / 10.0);
        let epss = sanitize_unit(input.max_epss);
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
        let amplified = (base * surface_uplift(input)).clamp(0.0, 1.0);
        let value = (amplified * exposure_factor * criticality_factor * 100.0).clamp(0.0, 100.0);

        Self {
            value,
            band: RiskBand::from_value(value),
            confidence: input.confidence,
        }
    }
}

/// Clamp `x` to `0.0..=1.0`, mapping any non-finite value to `0.0`.
///
/// `f32::clamp` alone returns `self` for `NaN`, so it cannot sanitise a
/// malformed input on its own.
fn sanitize_unit(x: f32) -> f32 {
    if x.is_finite() {
        x.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Attack-surface multiplier `1.0 ..= 1.0 + SURFACE_MAX_UPLIFT`.
///
/// Critical findings count fully, High at half; Medium/Low are excluded —
/// they inflate the count without materially adding remotely exploitable
/// paths. The single worst finding is already fully reflected in `severity`,
/// so only weighted findings *beyond* it drive the uplift, which saturates
/// (`1 - e^-x`) so a host is never scored on raw CVE volume alone.
fn surface_uplift(input: &RiskInputs) -> f32 {
    // u16::from keeps the count→f32 conversion exact (counts never approach
    // f32's 2^24 integer limit); an implausibly huge count saturates at u16.
    let critical = f32::from(u16::try_from(input.critical_vulns).unwrap_or(u16::MAX));
    let high = f32::from(u16::try_from(input.high_vulns).unwrap_or(u16::MAX));
    let weighted = 0.5f32.mul_add(high, critical);
    // Subtract the *actual* weight of the single worst finding (already counted
    // in `severity`): 1.0 if a Critical drives the score, 0.5 if the worst is a
    // High, 0.0 if there are no serious findings. A flat 1.0 here zeroed the
    // uplift for High-only hosts (two Highs weigh 1.0 → nothing "beyond"),
    // contradicting the rule that the 2nd serious finding should move the score.
    let worst_weight = if critical >= 1.0 {
        1.0
    } else if high >= 1.0 {
        0.5
    } else {
        0.0
    };
    let beyond_worst = (weighted - worst_weight).max(0.0);
    let surface = 1.0 - (-beyond_worst / SURFACE_SCALE).exp();
    SURFACE_MAX_UPLIFT.mul_add(surface, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single worst-case finding (one Critical CVE) — the baseline the
    /// attack-surface uplift builds on.
    fn one_critical(exposure: Exposure, criticality: Criticality) -> RiskInputs {
        RiskInputs {
            max_cvss: 10.0,
            max_epss: 1.0,
            kev_present: true,
            critical_vulns: 1,
            high_vulns: 0,
            exposure,
            criticality,
            confidence: Confidence::Confirmed,
        }
    }

    #[test]
    fn worst_case_is_critical() {
        let s = RiskScore::compute(&one_critical(
            Exposure::InternetFacing,
            Criticality::Critical,
        ));
        assert!((s.value - 100.0).abs() < f32::EPSILON);
        assert_eq!(s.band, RiskBand::Critical);
    }

    #[test]
    fn benign_case_is_info() {
        let s = RiskScore::compute(&RiskInputs {
            max_cvss: 0.0,
            max_epss: 0.0,
            kev_present: false,
            critical_vulns: 0,
            high_vulns: 0,
            exposure: Exposure::Internal,
            criticality: Criticality::Low,
            confidence: Confidence::Confirmed,
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
            critical_vulns: 0,
            high_vulns: 1,
            exposure: Exposure::Internal,
            criticality: Criticality::Medium,
            confidence: Confidence::High,
        };
        let with_kev = RiskInputs {
            kev_present: true,
            ..base
        };
        assert!(RiskScore::compute(&with_kev).value > RiskScore::compute(&base).value);
    }

    #[test]
    fn a_single_finding_is_unaffected_by_the_surface_uplift() {
        // One serious finding must score exactly as it did before volume was
        // modelled: the uplift only applies to findings beyond the worst.
        let internal = one_critical(Exposure::Internal, Criticality::Medium);
        let lone = RiskScore::compute(&internal);
        let manual = (0.6_f32 + 0.4) /* base, cvss10+kev */ * 0.7 * 0.75 * 100.0;
        assert!((lone.value - manual).abs() < 1e-3);
    }

    #[test]
    fn attack_surface_raises_score_with_serious_volume() {
        let base = RiskInputs {
            max_cvss: 8.0,
            max_epss: 0.2,
            kev_present: false,
            critical_vulns: 1,
            high_vulns: 0,
            exposure: Exposure::InternetFacing,
            criticality: Criticality::High,
            confidence: Confidence::Confirmed,
        };
        let many = RiskInputs {
            critical_vulns: 30,
            ..base
        };
        assert!(RiskScore::compute(&many).value > RiskScore::compute(&base).value);
    }

    #[test]
    fn the_uplift_saturates_so_volume_never_dominates() {
        let mk = |n: u32| RiskInputs {
            max_cvss: 8.0,
            max_epss: 0.2,
            kev_present: false,
            critical_vulns: n,
            high_vulns: 0,
            exposure: Exposure::InternetFacing,
            criticality: Criticality::High,
            confidence: Confidence::Confirmed,
        };
        let forty = RiskScore::compute(&mk(40)).value;
        let twohundred = RiskScore::compute(&mk(200)).value;
        // Five-fold more findings barely moves the score once saturated, and
        // the uplift never exceeds SURFACE_MAX_UPLIFT over the lone-finding base.
        assert!((twohundred - forty).abs() < 0.5);
        let lone = RiskScore::compute(&mk(1)).value;
        assert!(twohundred <= lone * (1.0 + SURFACE_MAX_UPLIFT) + 1e-3);
    }

    #[test]
    fn two_high_findings_engage_the_surface_uplift() {
        // Regression: the worst finding's weight (0.5 for a High) is what gets
        // subtracted, so a 2nd High *beyond* the worst lifts the score. The old
        // flat 1.0 subtraction zeroed the uplift for High-only hosts (this test
        // would fail then: one and two Highs scored identically).
        let base = RiskInputs {
            max_cvss: 7.5,
            max_epss: 0.2,
            kev_present: false,
            critical_vulns: 0,
            high_vulns: 1,
            exposure: Exposure::InternetFacing,
            criticality: Criticality::High,
            confidence: Confidence::Confirmed,
        };
        let two = RiskInputs {
            high_vulns: 2,
            ..base
        };
        assert!(RiskScore::compute(&two).value > RiskScore::compute(&base).value);
    }

    #[test]
    fn non_finite_inputs_never_produce_a_nan_score() {
        // A malformed feed value (NaN/Inf CVSS or EPSS) must not poison the
        // score into NaN — which `from_value` would silently band as `Info`.
        for (cvss, epss) in [
            (f32::NAN, 0.5),
            (9.8, f32::NAN),
            (f32::INFINITY, f32::NEG_INFINITY),
        ] {
            let s = RiskScore::compute(&RiskInputs {
                max_cvss: cvss,
                max_epss: epss,
                kev_present: false,
                critical_vulns: 0,
                high_vulns: 0,
                exposure: Exposure::InternetFacing,
                criticality: Criticality::Critical,
                confidence: Confidence::Confirmed,
            });
            assert!(
                s.value.is_finite(),
                "score must stay finite for {cvss}/{epss}"
            );
            assert!((0.0..=100.0).contains(&s.value));
        }
    }

    #[test]
    fn all_bands_is_exhaustive() {
        for b in RiskBand::ALL {
            match b {
                RiskBand::Info
                | RiskBand::Low
                | RiskBand::Medium
                | RiskBand::High
                | RiskBand::Critical => {}
            }
        }
        assert_eq!(RiskBand::ALL.len(), 5);
    }

    #[test]
    fn high_severity_counts_half_of_critical() {
        let two_high = RiskInputs {
            max_cvss: 8.0,
            max_epss: 0.2,
            kev_present: false,
            critical_vulns: 0,
            high_vulns: 3,
            exposure: Exposure::InternetFacing,
            criticality: Criticality::High,
            confidence: Confidence::Confirmed,
        };
        let two_crit = RiskInputs {
            critical_vulns: 2,
            high_vulns: 1,
            ..two_high
        };
        // Same max_cvss, but more weighted serious findings → higher score.
        assert!(RiskScore::compute(&two_crit).value > RiskScore::compute(&two_high).value);
    }
}

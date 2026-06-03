//! Findings: individual observations attached to assets.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::{AssetId, FindingId};
use crate::vuln::Severity;

/// Where a finding originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    /// Produced by an active scan.
    ActiveScan,
    /// Produced by the passive sensor.
    PassiveSensor,
    /// Pulled from an external integration / connector.
    Integration,
    /// Entered manually by an analyst.
    Manual,
}

/// Confidence level of a finding. Ordered `Low < Medium < High < Confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Weak signal.
    Low,
    /// Moderate signal.
    Medium,
    /// Strong signal.
    High,
    /// Verified / confirmed.
    Confirmed,
}

/// A single observation about an asset (open service, weakness, policy gap, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier.
    pub id: FindingId,
    /// Asset this finding belongs to.
    pub asset_id: AssetId,
    /// Short title.
    pub title: String,
    /// Longer description.
    pub description: String,
    /// Origin of the finding.
    pub source: FindingSource,
    /// Confidence in the finding.
    pub confidence: Confidence,
    /// Severity.
    pub severity: Severity,
    /// When it was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_carries_its_asset_and_severity() {
        let asset_id = AssetId::new();
        let f = Finding {
            id: FindingId::new(),
            asset_id,
            title: "Open Telnet".into(),
            description: "Telnet (23/tcp) exposed without encryption".into(),
            source: FindingSource::ActiveScan,
            confidence: Confidence::High,
            severity: Severity::High,
            observed_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(f.asset_id, asset_id);
        assert_eq!(f.severity, Severity::High);
        assert!(f.confidence >= Confidence::Medium);
    }
}

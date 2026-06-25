//! The central [`Asset`] entity and its classification value objects.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::AssetId;
use crate::network::Interface;

/// Broad class of an asset, mirroring the IT/OT/IoT/IoMT taxonomy.
///
/// `Ord`/`Hash` are derived so callers can group or sort assets by type
/// directly (e.g. a `BTreeMap<AssetType, _>`) instead of keying on the fragile
/// `Debug` string. Order follows declaration order and carries no severity
/// meaning.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    /// Traditional IT (servers, workstations, laptops).
    It,
    /// Operational Technology (PLCs, SCADA, industrial controllers).
    Ot,
    /// Internet of Things (cameras, sensors, smart devices).
    Iot,
    /// Internet of Medical Things (medical devices).
    Iomt,
    /// Network infrastructure (switches, routers, firewalls).
    Network,
    /// Cloud workload or managed cloud resource.
    Cloud,
    /// Mobile device.
    Mobile,
    /// Not yet classified.
    #[default]
    Unknown,
}

impl AssetType {
    /// Every variant, in declaration order — the single source of truth for
    /// callers that must enumerate all types (reports, dashboards). Adding a
    /// variant without extending this is caught by `all_covers_every_variant`
    /// in the tests, so a new type can never be silently dropped from a report.
    pub const ALL: [Self; 8] = [
        Self::It,
        Self::Ot,
        Self::Iot,
        Self::Iomt,
        Self::Network,
        Self::Cloud,
        Self::Mobile,
        Self::Unknown,
    ];
}

/// Business criticality of an asset. Ordered: `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    /// Low business impact.
    #[default]
    Low,
    /// Moderate business impact.
    Medium,
    /// High business impact.
    High,
    /// Mission-critical.
    Critical,
}

impl Criticality {
    /// Every level, in declaration order (`Low`..`Critical`). Single source of
    /// truth for callers that enumerate all levels; kept exhaustive by
    /// `all_covers_every_variant`.
    pub const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];
}

/// Network exposure of an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// Reachable only from internal networks.
    Internal,
    /// Reachable from the public internet.
    InternetFacing,
    /// Exposure not yet determined.
    #[default]
    Unknown,
}

/// Result of device fingerprinting / classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Fingerprint {
    /// Device type label (e.g. `router`, `windows-workstation`).
    pub device_type: Option<String>,
    /// Vendor / manufacturer (e.g. resolved from MAC OUI).
    pub vendor: Option<String>,
    /// Operating system, if detected.
    pub os: Option<String>,
    /// Model / hardware identifier (e.g. `Raspberry Pi 4`, `HP LaserJet M404`).
    #[serde(default)]
    pub model: Option<String>,
    /// Classifier confidence, `0..=100`.
    pub confidence: u8,
    /// Signals that contributed to this fingerprint, for explainability
    /// (e.g. `["oui:Raspberry Pi", "mdns:raspberrypi.local", "rdns:pi.lan"]`).
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// A single real-world device, deduplicated across all data sources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    /// Stable identifier.
    pub id: AssetId,
    /// Classified asset type.
    pub asset_type: AssetType,
    /// Business criticality.
    pub criticality: Criticality,
    /// Network exposure.
    pub exposure: Exposure,
    /// Fingerprint / classification result.
    pub fingerprint: Fingerprint,
    /// Known network interfaces.
    pub interfaces: Vec<Interface>,
    /// First time this asset was observed.
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen: OffsetDateTime,
    /// Most recent observation.
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}

impl Asset {
    /// Correlation key used to deduplicate observations into one asset.
    ///
    /// Preference order: first MAC address, then first IP address, then the
    /// asset's own id as a last resort.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        if let Some(mac) = self.interfaces.iter().find_map(|i| i.mac) {
            return format!("mac:{mac}");
        }
        if let Some(ip) = self.interfaces.iter().find_map(|i| i.ip) {
            return format!("ip:{ip}");
        }
        format!("id:{}", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MacAddr;

    fn empty_asset() -> Asset {
        Asset {
            id: AssetId::new(),
            asset_type: AssetType::Unknown,
            criticality: Criticality::Low,
            exposure: Exposure::Unknown,
            fingerprint: Fingerprint::default(),
            interfaces: Vec::new(),
            first_seen: OffsetDateTime::UNIX_EPOCH,
            last_seen: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn dedup_key_prefers_mac() {
        let mut a = empty_asset();
        a.interfaces.push(Interface {
            mac: Some(MacAddr([0, 1, 2, 3, 4, 5])),
            ..Interface::default()
        });
        assert_eq!(a.dedup_key(), "mac:00:01:02:03:04:05");
    }

    #[test]
    fn dedup_key_falls_back_to_id() {
        let a = empty_asset();
        assert_eq!(a.dedup_key(), format!("id:{}", a.id));
    }

    #[test]
    fn criticality_is_ordered() {
        assert!(Criticality::Critical > Criticality::Low);
    }

    #[test]
    fn all_covers_every_variant() {
        // The exhaustive matches below stop compiling the moment a variant is
        // added without being placed in `ALL` — turning a silent report-drop
        // into a build failure. The length asserts pin the count.
        for t in AssetType::ALL {
            match t {
                AssetType::It
                | AssetType::Ot
                | AssetType::Iot
                | AssetType::Iomt
                | AssetType::Network
                | AssetType::Cloud
                | AssetType::Mobile
                | AssetType::Unknown => {}
            }
        }
        assert_eq!(AssetType::ALL.len(), 8);

        for c in Criticality::ALL {
            match c {
                Criticality::Low
                | Criticality::Medium
                | Criticality::High
                | Criticality::Critical => {}
            }
        }
        assert_eq!(Criticality::ALL.len(), 4);
    }
}

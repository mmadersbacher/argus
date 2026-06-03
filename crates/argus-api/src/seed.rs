//! In-memory seed data so the API (and the web console) have something real to
//! render before the Postgres-backed inventory lands in P1.

use std::net::{IpAddr, Ipv4Addr};

use argus_core::{
    Asset, AssetId, AssetType, Criticality, Exposure, Fingerprint, Interface, MacAddr, RiskBand,
    RiskInputs, RiskScore,
};
use serde::Serialize;
use time::OffsetDateTime;

/// An asset together with its computed risk score, as returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct ScoredAsset {
    /// The underlying asset (flattened into the JSON object).
    #[serde(flatten)]
    pub asset: Asset,
    /// Composite exposure/risk score.
    pub risk: RiskScore,
}

/// Aggregate numbers for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Total number of known assets.
    pub total_assets: usize,
    /// How many are internet-facing.
    pub internet_facing: usize,
    /// How many sit in the High or Critical risk band.
    pub critical_or_high: usize,
    /// Mean risk score across all assets, `0.0..=100.0`.
    pub avg_risk: f32,
}

impl Summary {
    /// Compute a [`Summary`] from a slice of scored assets.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn from_assets(assets: &[ScoredAsset]) -> Self {
        let total_assets = assets.len();
        let internet_facing = assets
            .iter()
            .filter(|a| a.asset.exposure == Exposure::InternetFacing)
            .count();
        let critical_or_high = assets
            .iter()
            .filter(|a| matches!(a.risk.band, RiskBand::High | RiskBand::Critical))
            .count();
        let avg_risk = if total_assets == 0 {
            0.0
        } else {
            assets.iter().map(|a| a.risk.value).sum::<f32>() / total_assets as f32
        };
        Self {
            total_assets,
            internet_facing,
            critical_or_high,
            avg_risk,
        }
    }
}

/// Static description of one seeded asset.
struct SeedSpec {
    asset_type: AssetType,
    criticality: Criticality,
    exposure: Exposure,
    vendor: &'static str,
    os: &'static str,
    device_type: &'static str,
    mac: [u8; 6],
    ip: [u8; 4],
    max_cvss: f32,
    max_epss: f32,
    kev: bool,
}

fn specs() -> Vec<SeedSpec> {
    vec![
        SeedSpec {
            asset_type: AssetType::It,
            criticality: Criticality::High,
            exposure: Exposure::InternetFacing,
            vendor: "Canonical",
            os: "Ubuntu 22.04",
            device_type: "web-server",
            mac: [0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c],
            ip: [203, 0, 113, 10],
            max_cvss: 9.8,
            max_epss: 0.92,
            kev: true,
        },
        SeedSpec {
            asset_type: AssetType::It,
            criticality: Criticality::Medium,
            exposure: Exposure::Internal,
            vendor: "Dell Inc.",
            os: "Windows 11",
            device_type: "workstation",
            mac: [0xb8, 0x85, 0x84, 0x10, 0x20, 0x30],
            ip: [10, 0, 5, 42],
            max_cvss: 6.5,
            max_epss: 0.08,
            kev: false,
        },
        SeedSpec {
            asset_type: AssetType::Network,
            criticality: Criticality::Critical,
            exposure: Exposure::Internal,
            vendor: "Cisco Systems",
            os: "IOS XE",
            device_type: "core-switch",
            mac: [0x00, 0x1b, 0x0d, 0x55, 0x66, 0x77],
            ip: [10, 0, 0, 1],
            max_cvss: 8.1,
            max_epss: 0.45,
            kev: true,
        },
        SeedSpec {
            asset_type: AssetType::Iot,
            criticality: Criticality::Low,
            exposure: Exposure::Internal,
            vendor: "Hikvision",
            os: "embedded-linux",
            device_type: "ip-camera",
            mac: [0xc0, 0x56, 0xe3, 0xaa, 0xbb, 0xcc],
            ip: [10, 0, 9, 17],
            max_cvss: 7.2,
            max_epss: 0.30,
            kev: false,
        },
        SeedSpec {
            asset_type: AssetType::Ot,
            criticality: Criticality::Critical,
            exposure: Exposure::Internal,
            vendor: "Siemens",
            os: "SIMATIC S7",
            device_type: "plc",
            mac: [0x00, 0x1c, 0x06, 0xde, 0xad, 0x01],
            ip: [192, 168, 50, 5],
            max_cvss: 5.3,
            max_epss: 0.02,
            kev: false,
        },
        SeedSpec {
            asset_type: AssetType::Iomt,
            criticality: Criticality::High,
            exposure: Exposure::Internal,
            vendor: "GE Healthcare",
            os: "embedded",
            device_type: "infusion-pump",
            mac: [0x00, 0x80, 0x64, 0x12, 0x34, 0x56],
            ip: [192, 168, 60, 22],
            max_cvss: 9.1,
            max_epss: 0.15,
            kev: false,
        },
    ]
}

/// Build the seeded, risk-scored asset list.
#[must_use]
pub fn seed_assets() -> Vec<ScoredAsset> {
    let now = OffsetDateTime::now_utc();
    specs()
        .into_iter()
        .map(|s| {
            let interfaces = vec![Interface {
                mac: Some(MacAddr(s.mac)),
                ip: Some(IpAddr::V4(Ipv4Addr::new(
                    s.ip[0], s.ip[1], s.ip[2], s.ip[3],
                ))),
                vlan: None,
                hostname: None,
            }];
            let asset = Asset {
                id: AssetId::new(),
                asset_type: s.asset_type,
                criticality: s.criticality,
                exposure: s.exposure,
                fingerprint: Fingerprint {
                    device_type: Some(s.device_type.to_owned()),
                    vendor: Some(s.vendor.to_owned()),
                    os: Some(s.os.to_owned()),
                    confidence: 80,
                },
                interfaces,
                first_seen: now,
                last_seen: now,
            };
            let risk = RiskScore::compute(&RiskInputs {
                max_cvss: s.max_cvss,
                max_epss: s.max_epss,
                kev_present: s.kev,
                exposure: s.exposure,
                criticality: s.criticality,
            });
            ScoredAsset { asset, risk }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_has_several_assets() {
        assert!(seed_assets().len() >= 5);
    }

    #[test]
    fn summary_counts_are_consistent() {
        let assets = seed_assets();
        let s = Summary::from_assets(&assets);
        assert_eq!(s.total_assets, assets.len());
        assert!(s.internet_facing >= 1);
        assert!(s.critical_or_high >= 1);
        assert!((0.0..=100.0).contains(&s.avg_risk));
    }

    #[test]
    fn scored_asset_serializes_flat_with_risk_and_rfc3339() {
        let assets = seed_assets();
        let json = serde_json::to_string(&assets[0]).expect("serialize");
        assert!(json.contains("\"risk\""));
        assert!(json.contains("\"first_seen\""));
        // RFC3339 timestamps contain a 'T' separator and look like 2026-..T..Z
        assert!(json.contains('T'));
    }
}

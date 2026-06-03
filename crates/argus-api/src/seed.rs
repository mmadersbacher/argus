//! The API view-model (`ScoredAsset`, `Summary`), in-memory seed data, and the
//! mapping from a discovery result into a scored asset.
//!
//! Risk for both seed and discovered assets is derived the same way: correlate
//! the asset's services against the `argus-vuln` CVE catalog, then score.

use std::net::{IpAddr, Ipv4Addr};

use argus_core::{
    Asset, AssetId, AssetType, Criticality, Exposure, Fingerprint, Interface, MacAddr, Protocol,
    RiskBand, RiskScore, Service, Vulnerability,
};
use argus_discovery::DiscoveredHost;
use serde::Serialize;
use time::OffsetDateTime;

/// An asset together with its services, correlated CVEs and computed risk.
#[derive(Debug, Clone, Serialize)]
pub struct ScoredAsset {
    /// The underlying asset (flattened into the JSON object).
    #[serde(flatten)]
    pub asset: Asset,
    /// Observed network services.
    pub services: Vec<Service>,
    /// Correlated vulnerabilities (CVEs) from the asset's services.
    pub vulnerabilities: Vec<Vulnerability>,
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

/// Score an asset from its services via CVE correlation.
fn score(
    services: &[Service],
    exposure: Exposure,
    criticality: Criticality,
) -> (Vec<Vulnerability>, RiskScore) {
    let vulnerabilities = argus_vuln::correlate_services(services);
    let risk = RiskScore::compute(&argus_vuln::risk_inputs(
        &vulnerabilities,
        exposure,
        criticality,
    ));
    (vulnerabilities, risk)
}

/// Map a discovered host into a scored asset (real CVE-backed risk).
#[must_use]
pub fn scored_from_discovered(host: DiscoveredHost) -> ScoredAsset {
    let (vulnerabilities, risk) =
        score(&host.services, host.asset.exposure, host.asset.criticality);
    ScoredAsset {
        asset: host.asset,
        services: host.services,
        vulnerabilities,
        risk,
    }
}

struct SeedSpec {
    asset_type: AssetType,
    criticality: Criticality,
    exposure: Exposure,
    vendor: &'static str,
    os: &'static str,
    device_type: &'static str,
    mac: [u8; 6],
    ip: [u8; 4],
    /// (port, service product) — products feed CVE correlation.
    services: &'static [(u16, &'static str)],
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
            services: &[
                (22, "OpenSSH 8.9p1"),
                (80, "Apache httpd 2.4.49"),
                (443, "Apache httpd 2.4.49"),
            ],
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
            services: &[(139, "smb"), (445, "smb"), (3389, "rdp")],
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
            services: &[(22, "OpenSSH 8.6"), (443, "https")],
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
            services: &[(80, "Hikvision IP Camera"), (443, "https")],
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
            services: &[(502, "Siemens SIMATIC S7")],
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
            services: &[(443, "https")],
        },
    ]
}

/// Build the seeded, CVE-correlated, risk-scored asset list.
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
            let services: Vec<Service> = s
                .services
                .iter()
                .map(|&(port, product)| Service {
                    port,
                    protocol: Protocol::Tcp,
                    product: Some(product.to_owned()),
                    banner: None,
                })
                .collect();
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
            let (vulnerabilities, risk) = score(&services, s.exposure, s.criticality);
            ScoredAsset {
                asset,
                services,
                vulnerabilities,
                risk,
            }
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

    fn web_server(assets: &[ScoredAsset]) -> &ScoredAsset {
        assets
            .iter()
            .find(|a| a.asset.fingerprint.device_type.as_deref() == Some("web-server"))
            .expect("web-server seed asset")
    }

    #[test]
    fn seed_correlates_real_cves() {
        let assets = seed_assets();
        let web = web_server(&assets);
        // Apache 2.4.49 → CVE-2021-41773
        assert!(web
            .vulnerabilities
            .iter()
            .any(|v| v.cve_id == "CVE-2021-41773"));
        assert!(!web.vulnerabilities.is_empty());
    }

    #[test]
    fn scored_asset_serializes_with_vulns_and_rfc3339() {
        let assets = seed_assets();
        let json = serde_json::to_string(web_server(&assets)).expect("serialize");
        assert!(json.contains("\"risk\""));
        assert!(json.contains("\"vulnerabilities\""));
        assert!(json.contains("\"services\""));
        assert!(json.contains("CVE-"));
        assert!(json.contains('T'));
    }

    #[test]
    fn discovered_host_with_vulnerable_service_scores() {
        let host = DiscoveredHost {
            asset: Asset {
                id: AssetId::new(),
                asset_type: AssetType::Network,
                criticality: Criticality::High,
                exposure: Exposure::InternetFacing,
                fingerprint: Fingerprint::default(),
                interfaces: Vec::new(),
                first_seen: OffsetDateTime::UNIX_EPOCH,
                last_seen: OffsetDateTime::UNIX_EPOCH,
            },
            services: vec![Service {
                port: 3389,
                protocol: Protocol::Tcp,
                product: Some("rdp".to_owned()),
                banner: None,
            }],
            open_ports: vec![3389],
            insecure_score: 0.0,
        };
        let scored = scored_from_discovered(host);
        assert!(scored
            .vulnerabilities
            .iter()
            .any(|v| v.cve_id == "CVE-2019-0708"));
        assert!(scored.risk.value > 0.0);
    }
}

//! Signal fusion: one confident device identity from many weak signals.
//!
//! Combines the signals a scan collects — MAC/OUI vendor, open-port pattern,
//! service banners/products, resolved hostname — into a device identity (type,
//! vendor, OS, model) with an explainable `evidence` trail and a `0..=100`
//! confidence. The runZero-style idea: no single unauthenticated signal is
//! decisive, but corroboration is.
//!
//! Runs as a post-pass after [`crate::enrich_macs`] (so the OUI vendor is set)
//! and after any banner/hostname enrichment.

use argus_core::AssetType;

use crate::DiscoveredHost;

/// Refine every host's fingerprint by fusing its collected signals.
pub fn fuse_hosts(hosts: &mut [DiscoveredHost]) {
    for host in hosts.iter_mut() {
        fuse_one(host);
    }
}

/// A vendor-driven device profile: (device_type, asset_type, os, model).
type Profile = (
    &'static str,
    AssetType,
    Option<&'static str>,
    Option<&'static str>,
);

/// Map a MAC/OUI vendor string to a device profile. Substring match on a
/// lowercased vendor, so "Raspberry Pi Foundation" and "Raspberry Pi (Trading)
/// Ltd" both hit. `ports` disambiguates a few multi-role vendors (Apple).
fn vendor_profile(vendor: &str, ports: &[u16]) -> Option<Profile> {
    let v = vendor.to_lowercase();
    let has = |p: u16| ports.contains(&p);
    let printer = has(9100) || has(631) || has(515);
    Some(match () {
        () if v.contains("raspberry pi") => (
            "single-board-computer",
            AssetType::It,
            Some("Linux"),
            Some("Raspberry Pi"),
        ),
        () if v.contains("espressif") => ("iot-device", AssetType::Iot, None, None),
        () if v.contains("mikrotik") => ("router", AssetType::Network, Some("RouterOS"), None),
        () if v.contains("ubiquiti") => ("network-device", AssetType::Network, None, None),
        () if v.contains("cisco") || v.contains("juniper") || v.contains("aruba") => {
            ("network-device", AssetType::Network, None, None)
        }
        () if v.contains("avm") => ("router", AssetType::Network, None, Some("FRITZ!Box")),
        () if v.contains("tp-link")
            || v.contains("netgear")
            || v.contains("d-link")
            || v.contains("zyxel")
            || v.contains("asustek")
            || v.contains("ruckus") =>
        {
            ("router-or-ap", AssetType::Network, None, None)
        }
        () if v.contains("synology") || v.contains("qnap") => {
            ("nas", AssetType::It, Some("Linux"), None)
        }
        () if (v.contains("hewlett")
            || v.contains("hp inc")
            || v.contains("canon")
            || v.contains("epson")
            || v.contains("brother")
            || v.contains("lexmark"))
            && printer =>
        {
            ("printer", AssetType::Iot, None, None)
        }
        () if v.contains("apple") => {
            // A Mac exposes server ports; a bare iPhone/iPad does not.
            if has(22) || has(445) || has(548) || has(5900) {
                ("apple-computer", AssetType::It, Some("macOS"), None)
            } else {
                ("apple-mobile", AssetType::Mobile, None, None)
            }
        }
        () if v.contains("samsung")
            || v.contains("google")
            || v.contains("nest")
            || v.contains("amazon")
            || v.contains("sonos")
            || v.contains("roku")
            || v.contains("lg electronics") =>
        {
            ("smart-home-or-media", AssetType::Iot, None, None)
        }
        () if v.contains("axis") || v.contains("hikvision") || v.contains("dahua") => {
            ("ip-camera", AssetType::Iot, None, None)
        }
        () => return None,
    })
}

/// Derive an OS string from any service banner/product text.
fn os_from_banners(banners: &[String]) -> Option<String> {
    let hay = banners.join(" ").to_lowercase();
    let os = if hay.contains("raspbian") || hay.contains("raspberry") {
        "Linux (Raspberry Pi OS)"
    } else if hay.contains("debian") {
        "Linux (Debian)"
    } else if hay.contains("ubuntu") {
        "Linux (Ubuntu)"
    } else if hay.contains("routeros") || hay.contains("mikrotik") {
        "RouterOS"
    } else if hay.contains("windows") || hay.contains("microsoft-ds") {
        "Windows"
    } else if hay.contains("freebsd") {
        "FreeBSD"
    } else if hay.contains("openwrt") {
        "Linux (OpenWrt)"
    } else {
        return None;
    };
    Some(os.to_owned())
}

fn fuse_one(host: &mut DiscoveredHost) {
    let ports = host.open_ports.clone();
    let vendor = host.asset.fingerprint.vendor.clone();
    let hostnames: Vec<String> = host
        .asset
        .interfaces
        .iter()
        .filter_map(|i| i.hostname.clone())
        .collect();
    let banners: Vec<String> = host
        .services
        .iter()
        .filter_map(|s| s.banner.clone().or_else(|| s.product.clone()))
        .collect();

    let fp = &mut host.asset.fingerprint;
    let mut evidence: Vec<String> = Vec::new();
    // Base confidence: a port-pattern classification alone is a weak guess.
    let mut conf: u32 = if ports.is_empty() { 10 } else { 35 };

    if let Some(v) = &vendor {
        evidence.push(format!("oui:{v}"));
        conf += 15;
        if let Some((device_type, asset_type, os, model)) = vendor_profile(v, &ports) {
            fp.device_type = Some(device_type.to_owned());
            host.asset.asset_type = asset_type;
            conf += 15; // a recognised vendor profile is a strong corroborator
            if let Some(os) = os {
                fp.os.get_or_insert_with(|| os.to_owned());
            }
            if let Some(model) = model {
                fp.model.get_or_insert_with(|| model.to_owned());
            }
        }
    }

    if let Some(os) = os_from_banners(&banners) {
        evidence.push(format!("banner-os:{os}"));
        conf += 15;
        fp.os = Some(os);
    }

    if let Some(hostname) = hostnames.first() {
        evidence.push(format!("hostname:{hostname}"));
        conf += 10;
        let lower = hostname.to_lowercase();
        if lower.contains("raspberrypi") || lower.contains("raspberry") {
            fp.model.get_or_insert_with(|| "Raspberry Pi".to_owned());
            fp.os
                .get_or_insert_with(|| "Linux (Raspberry Pi OS)".to_owned());
        }
    }

    if !ports.is_empty() {
        evidence.push(format!("ports:{}", ports.len()));
    }

    fp.confidence = u8::try_from(conf.min(95)).unwrap_or(95);
    fp.evidence = evidence;
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::{
        Asset, AssetId, Criticality, Exposure, Fingerprint, Interface, Protocol, Service,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use time::OffsetDateTime;

    fn host(
        vendor: Option<&str>,
        ports: Vec<u16>,
        banner: Option<&str>,
        hostname: Option<&str>,
    ) -> DiscoveredHost {
        let now = OffsetDateTime::now_utc();
        DiscoveredHost {
            asset: Asset {
                id: AssetId::new(),
                asset_type: AssetType::Unknown,
                criticality: Criticality::Medium,
                exposure: Exposure::Internal,
                fingerprint: Fingerprint {
                    vendor: vendor.map(str::to_owned),
                    ..Fingerprint::default()
                },
                interfaces: vec![Interface {
                    mac: None,
                    ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 8, 50))),
                    vlan: None,
                    hostname: hostname.map(str::to_owned),
                }],
                first_seen: now,
                last_seen: now,
            },
            services: banner
                .map(|b| {
                    vec![Service {
                        port: 22,
                        protocol: Protocol::Tcp,
                        product: None,
                        banner: Some(b.to_owned()),
                        cpe: None,
                    }]
                })
                .unwrap_or_default(),
            open_ports: ports,
            insecure_score: 0.0,
            smb_v1: None,
        }
    }

    #[test]
    fn raspberry_pi_is_recognised_from_oui_plus_banner() {
        let mut h = host(
            Some("Raspberry Pi Foundation"),
            vec![22],
            Some("SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u1"),
            None,
        );
        fuse_one(&mut h);
        let fp = &h.asset.fingerprint;
        assert_eq!(h.asset.asset_type, AssetType::It);
        assert_eq!(fp.device_type.as_deref(), Some("single-board-computer"));
        assert_eq!(fp.model.as_deref(), Some("Raspberry Pi"));
        assert!(fp.os.as_deref().unwrap().contains("Raspberry Pi OS"));
        assert!(
            fp.confidence >= 70,
            "corroborated identity is high-confidence"
        );
        assert!(fp.evidence.iter().any(|e| e.starts_with("oui:Raspberry")));
    }

    #[test]
    fn raspberry_pi_recognised_from_hostname_alone() {
        let mut h = host(None, vec![22], None, Some("raspberrypi.local"));
        fuse_one(&mut h);
        assert_eq!(h.asset.fingerprint.model.as_deref(), Some("Raspberry Pi"));
    }

    #[test]
    fn mikrotik_oui_becomes_network_device() {
        let mut h = host(Some("MikroTik"), vec![22, 8291], None, None);
        fuse_one(&mut h);
        assert_eq!(h.asset.asset_type, AssetType::Network);
        assert_eq!(h.asset.fingerprint.os.as_deref(), Some("RouterOS"));
    }

    #[test]
    fn unknown_vendor_no_ports_is_low_confidence() {
        let mut h = host(None, vec![], None, None);
        fuse_one(&mut h);
        assert!(h.asset.fingerprint.confidence <= 15);
    }
}

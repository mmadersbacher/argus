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
        // Single-purpose consumer-media/IoT OUIs only. Deliberately NOT here:
        // Samsung, LG, Google, Apple — conglomerates whose OUI ships on phones,
        // tablets, TVs, appliances and hubs alike, so the OUI cannot pin a class.
        // Those are left to a protocol signal (SSDP/mDNS/miIO) to classify, the
        // same discipline the Xiaomi miIO path enforces. Apple is handled above
        // (port-gated); Samsung/LG/Google get vendor-only until a probe confirms.
        () if v.contains("nest")
            || v.contains("amazon")
            || v.contains("sonos")
            || v.contains("roku") =>
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
    } else if hay.contains("windows")
        || hay.contains("microsoft-ds")
        || hay.contains("microsoft-iis")
    {
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

/// Infer a `(device_type, asset_type)` from a lowercased identity haystack built
/// from hostnames, service banners, product tokens and the model — the signals
/// SSDP / WS-Discovery / mDNS / HTTP / CoAP / TLS contribute. Used only as a
/// fallback when the MAC/OUI vendor profile did not already classify the host.
fn device_from_identity(hay: &str) -> Option<(&'static str, AssetType)> {
    let has = |k: &str| hay.contains(k);
    Some(match () {
        // Protocol-confirmed enterprise + OT identities win first — these come
        // from a service that named itself (LDAP rootDSE, Modbus/EtherNet/IP/
        // BACnet device id), not from a guess.
        () if has("domain-controller") => ("domain-controller", AssetType::It),
        () if has("modbus")
            || has("ethernet/ip")
            || has("bacnet")
            || has("rockwell")
            || has("allen-bradley")
            || has("logix")
            || has("siemens")
            || has("schneider")
            || has("industrial") =>
        {
            ("industrial-controller", AssetType::Ot)
        }
        () if has("mssql") || has("sql server") => ("database-server", AssetType::It),
        () if has("laserjet")
            || has("officejet")
            || has("printer")
            || has("print")
            || has("_ipp")
            || has("pdl") =>
        {
            ("printer", AssetType::Iot)
        }
        () if has("onvif")
            || has("networkvideotransmitter")
            || has("ipcam")
            || has("ip camera")
            || has("hikvision")
            || has("dahua")
            || has("nvr") =>
        {
            ("ip-camera", AssetType::Iot)
        }
        () if has("mediarenderer")
            || has("mediaserver")
            || has("roku")
            || has("chromecast")
            || has("googlecast")
            || has("appletv")
            || has("smarttv")
            || has("airplay") =>
        {
            ("media-device", AssetType::Iot)
        }
        () if has("internetgateway")
            || has("openwrt")
            || has("routeros")
            || has("dd-wrt")
            || has("fritz")
            || has("router")
            || has("gateway") =>
        {
            ("router-or-ap", AssetType::Network)
        }
        () if has("synology") || has("qnap") || has("truenas") || has("freenas") => {
            ("nas", AssetType::It)
        }
        () if has("raspberry") || has("raspbian") => ("single-board-computer", AssetType::It),
        () if has("espressif")
            || has("tasmota")
            || has("shelly")
            || has("sonoff")
            || has("tuya")
            || has("coap")
            || has("mqtt") =>
        {
            ("iot-device", AssetType::Iot)
        }
        () => return None,
    })
}

fn fuse_one(host: &mut DiscoveredHost) {
    let ports = host.open_ports.clone();
    let vendor = host.asset.fingerprint.vendor.clone();
    // A host present at L2 (it answered ARP, so it has a MAC) but with no open
    // scanned TCP port is the class only active-ARP discovery surfaces.
    let l2_only = ports.is_empty() && host.asset.interfaces.iter().any(|i| i.mac.is_some());
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
    // Service product tokens (e.g. "CoAP", "WS-Discovery", "SSDP/UPnP") feed the
    // identity fallback even when a service's banner is what `banners` captured.
    let products: Vec<String> = host
        .services
        .iter()
        .filter_map(|s| s.product.clone())
        .collect();
    // A miIO handshake (UDP 54321) is positive, unauthenticated proof of a Xiaomi
    // smart-home device — strong identity even with zero open TCP ports, and the
    // only signal that should lift a Xiaomi OUI past "unknown" (the OUI alone
    // spans phones and IoT alike, so it must not classify on its own).
    let is_miio = host
        .services
        .iter()
        .any(|s| s.product.as_deref() == Some("miIO"));

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
        // A Raspberry Pi OS banner (e.g. SSH "...Raspbian...") identifies the
        // device even across a NAT where no MAC/OUI or mDNS is available.
        if os.contains("Raspberry Pi") {
            fp.model.get_or_insert_with(|| "Raspberry Pi".to_owned());
            fp.device_type
                .get_or_insert_with(|| "single-board-computer".to_owned());
            host.asset.asset_type = AssetType::It;
        }
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

    // Protocol-grounded identity OVERRIDES a weak port-pattern guess and the OUI
    // profile: a device that announces what it is (SSDP/WSD/mDNS/IPP/RTSP/HTTP/TLS
    // strings, model, hostname) beats an inference from which ports it left open.
    // This is what makes a Samsung TV on :8080 read as a media-device, and an IPP
    // printer's make/model win over the bare port-class "printer".
    {
        let model = fp.model.clone().unwrap_or_default();
        let hay = format!(
            "{} {} {} {}",
            hostnames.join(" "),
            banners.join(" "),
            products.join(" "),
            model
        )
        .to_lowercase();
        if let Some((device_type, asset_type)) = device_from_identity(&hay) {
            if fp.device_type.as_deref() != Some(device_type) {
                evidence.push(format!("id:{device_type}"));
            }
            conf += 12;
            fp.device_type = Some(device_type.to_owned());
            host.asset.asset_type = asset_type;
        }
    }

    // miIO is definitive proof of a Xiaomi smart-home device and runs last so a
    // weaker signal cannot override it — but it yields (via get_or_insert) to a
    // more specific protocol identity, e.g. a Xiaomi camera already set ip-camera.
    if is_miio {
        evidence.push("miio".to_owned());
        conf += 25;
        fp.device_type
            .get_or_insert_with(|| "smart-home-device".to_owned());
        if host.asset.asset_type == AssetType::Unknown {
            host.asset.asset_type = AssetType::Iot;
        }
    }

    if !ports.is_empty() {
        evidence.push(format!("ports:{}", ports.len()));
    } else if l2_only {
        evidence.push("l2-only".to_owned());
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
    fn raspberry_pi_recognised_from_ssh_banner_alone() {
        // No OUI, no mDNS (the WSL-NAT / cross-subnet case): the SSH banner's
        // "Raspbian" token still identifies it as a Raspberry Pi.
        let mut h = host(
            None,
            vec![22],
            Some("SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u1"),
            None,
        );
        fuse_one(&mut h);
        assert_eq!(h.asset.asset_type, AssetType::It);
        assert_eq!(h.asset.fingerprint.model.as_deref(), Some("Raspberry Pi"));
        assert_eq!(
            h.asset.fingerprint.device_type.as_deref(),
            Some("single-board-computer")
        );
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

    #[test]
    fn miio_response_classifies_xiaomi_as_smart_home() {
        let mut h = host(
            Some("Beijing Xiaomi Mobile Software Co., Ltd"),
            vec![],
            None,
            None,
        );
        h.services.push(Service {
            port: 54321,
            protocol: Protocol::Udp,
            product: Some("miIO".to_owned()),
            banner: Some("device_id=0x2cc9f8a8 stamp=1".to_owned()),
            cpe: None,
        });
        fuse_one(&mut h);
        assert_eq!(h.asset.asset_type, AssetType::Iot);
        assert_eq!(
            h.asset.fingerprint.device_type.as_deref(),
            Some("smart-home-device")
        );
        assert!(h.asset.fingerprint.evidence.iter().any(|e| e == "miio"));
        assert!(h.asset.fingerprint.confidence >= 40);
    }

    #[test]
    fn xiaomi_oui_without_miio_stays_unclassified() {
        // The discipline the engine must hold: a Xiaomi OUI alone proves nothing
        // (the same prefix ships on phones and IoT), so with no positive protocol
        // signal the device must remain Unknown — never guessed as a phone or a
        // smart-home device.
        let mut h = host(
            Some("Beijing Xiaomi Mobile Software Co., Ltd"),
            vec![],
            None,
            None,
        );
        fuse_one(&mut h);
        assert_eq!(h.asset.asset_type, AssetType::Unknown);
        assert_eq!(h.asset.fingerprint.device_type, None);
    }

    #[test]
    fn samsung_oui_alone_does_not_assume_a_class() {
        // Same discipline beyond Xiaomi: Samsung ships phones, tablets, TVs,
        // fridges and SmartThings hubs on one OUI — the prefix alone must not
        // assert "smart-home". Only a protocol signal (SSDP/mDNS) may classify.
        let mut h = host(Some("Samsung Electronics Co.,Ltd"), vec![], None, None);
        fuse_one(&mut h);
        assert_eq!(h.asset.asset_type, AssetType::Unknown);
        assert_eq!(h.asset.fingerprint.device_type, None);
    }

    #[test]
    fn protocol_identity_overrides_port_class_guess() {
        // A device the port-class called "web-server" (e.g. a TV's HTTP on :8080)
        // must be reclassified when a protocol banner says what it really is.
        let mut h = host(None, vec![8080], None, None);
        h.asset.fingerprint.device_type = Some("web-server".to_owned()); // port-class guess
        h.services.push(Service {
            port: 5353,
            protocol: Protocol::Udp,
            product: Some("mDNS".to_owned()),
            banner: Some("_airplay._tcp, _spotify-connect._tcp".to_owned()),
            cpe: None,
        });
        fuse_one(&mut h);
        assert_eq!(
            h.asset.fingerprint.device_type.as_deref(),
            Some("media-device")
        );
        assert_eq!(h.asset.asset_type, AssetType::Iot);
    }

    #[test]
    fn ipp_make_and_model_keeps_printer_class() {
        // The IPP make/model banner corroborates the port-class "printer" and
        // flows the real model in via the identity haystack.
        let mut h = host(None, vec![631], None, None);
        h.asset.fingerprint.device_type = Some("printer".to_owned());
        h.services.push(Service {
            port: 631,
            protocol: Protocol::Tcp,
            product: None,
            banner: Some("ipp: HP LaserJet Pro M404 state=idle".to_owned()),
            cpe: None,
        });
        fuse_one(&mut h);
        assert_eq!(h.asset.fingerprint.device_type.as_deref(), Some("printer"));
        assert_eq!(h.asset.asset_type, AssetType::Iot);
    }
}
